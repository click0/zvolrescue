# Налагодження на тестовому пулі

**English version:** [DEBUGGING.md](DEBUGGING.md)

`zvolrescue` перевірено на синтетичних fixture. Перший справжній пул
десь із ним не погодиться — тип nvlist, якого він не бачив, деталь
розкладки ZAP-листка, feature flag. Ця сторінка — цикл пошуку того,
*де саме*, на одноразовому пулі у віртуальній машині.

Усе нижче не пише на пристрої пулу, крім кроків, які навмисно
створюють або псують *тестовий* пул.

## 1. Зібрати тестовий пул

FreeBSD (memory disks):

```sh
truncate -s 256m /tmp/m0.img /tmp/m1.img
mdconfig -a -t vnode -f /tmp/m0.img -u 10
mdconfig -a -t vnode -f /tmp/m1.img -u 11
zpool create -o ashift=12 tpool mirror md10 md11
zfs create tpool/vm
zfs create -V 32m -o volblocksize=8k tpool/vm/disk0
dd if=/dev/random of=/dev/zvol/tpool/vm/disk0 bs=8k count=1024 conv=sync
sha256 /dev/zvol/tpool/vm/disk0            # запам'ятати
zfs snapshot tpool/vm/disk0@before
zpool export tpool
```

На Linux (loop-пристрої) те саме з `losetup -f --show /tmp/m0.img`
замість `mdconfig`, `/dev/loop*` замість `md*` і `sha256sum`.

Перед читанням `zvolrescue` пул треба експортувати: імпортований пул
далі пише uberblock-и, і мітки «їдуть» під час перегляду. Після
експорту образи `/tmp/m0.img`, `/tmp/m1.img` — це evidence.

## 2. Звірити `scan` із `zdb`

```sh
zvolrescue -vv scan /tmp/m0.img /tmp/m1.img > scan.txt
zdb -l /tmp/m0.img                             # мітки + nvlist
zdb -lu /tmp/m0.img                            # + uberblock-и
```

Що має збігатися:

| `zvolrescue -vv scan` | `zdb -l` / `-lu` |
|---|---|
| ім'я пулу, `pool_guid`, `guid`, `top_guid`, `txg`, `hostname` | ті самі ключі в кожній мітці |
| `ashift`, діти `vdev_tree` з їхніми `path`/`guid` | `vdev_tree` |
| `features_for_read` | `features_for_read` |
| `txg`/`timestamp` uberblock-ів по мітках, best txg | рядки `Uberblock[N]`; `zdb -lu` друкує всі |
| checksum конфігу `ok` на всіх чотирьох мітках | `zdb` мовчить при успіху; `failed to unpack label` при збої |

Якщо у `-vv` бракує або спотворено ключ nvlist — парсер XDR помиляється
на цьому типі: запустіть із `--debug` і дивіться рядок `[label]` — при
помилці розбору він друкує перші 64 байти `vdev_phys`; порівняйте з
`zdb -l` і `hexdump -C -s $((16*1024)) -n 256 /tmp/m0.img`.

## 3. Звірити `list` із `zdb -d`

```sh
zvolrescue list -r /tmp/m0.img /tmp/m1.img
zdb -e -p /tmp -d tpool                       # -e/-p: експортований пул з образів
zdb -e -p /tmp -dddd tpool/vm/disk0           # об'єкти одного dataset-у
```

`zdb -d` друкує кожен dataset з номером об'єкта, типом і
`creation_txg`; `list` має показати ті самі імена, типи, guid і volsize.
Якщо `list` обривається раніше, `--debug` покаже останній прочитаний
каталог `[dsl]` і рядки `[dnode]`/`[zap]` після нього: номер об'єкта
звідти — те, що дивитися через `zdb -e -p /tmp -dddd tpool <obj>`.

## 4. Звірити `dump` з оригіналом

```sh
zvolrescue dump tpool/vm/disk0 /tmp/m0.img /tmp/m1.img -o /tmp/disk0.img --debug-log /tmp/trace.log
sha256 /tmp/disk0.img                          # дорівнює хешу з кроку 1
```

Розбіжність без жодного нечитабельного блоку означає, що блок
декодовано неправильно (стиснення, порядок байтів або дерево блоків).
Знайдіть перший відмінний зсув через `cmp /tmp/disk0.img
/dev/zvol/tpool/vm/disk0` (для цього пул треба знову імпортувати),
поділіть на `volblocksize` — це blkid, а в `/tmp/trace.log` шукайте
`locate blkid N` і рядки `[zio] read bp` після нього: там DVA, розміри,
стиснення та checksum кожного блоку, прочитаного для нього.

## 5. Як читати трасу `--debug`

Кожен рядок — `[модуль] …`. Модулі в порядку читання:

| Тег | Що повідомляє |
|---|---|
| `cli` | версія та argv |
| `label` | по мітках: checksum конфігу, результат nvlist, `ashift` → зсув слота uberblock, найкраща мітка |
| `uberblock` | по слотах: txg, timestamp, checksum, birth кореневого вказівника |
| `pool` | зібрані пули, top-level vdev, члени present/missing |
| `txg` | верифіковані uberblock-и `txg@devN/Lx`, з яких обирається |
| `dsl` | кореневий вказівник MOS, object directory, кожен відвіданий DSL-каталог і dataset |
| `dnode` | кожен прочитаний dnode: номер об'єкта, тип, рівні, вказівники, розмір блока, bonus |
| `dmu` | обхід дерева блоків: рівень, індекс, дочірній вказівник або HOLE |
| `zio` | кожне читання блоку: зведення вказівника, кожна спроба DVA/пристрою, результат checksum; очікувані й обчислені слова та hex-дамп при розбіжності, hex-дамп при збої декомпресії |
| `zap` | тип блоку, поля заголовка, листкові блоки, імена записів |
| `zvol` | геометрія витягання і кожен нечитабельний блок |

Hex-дампи мають розкладку `hexdump -C` зі зсувом *на пристрої* (зсув
мітки або `4 MiB + DVA-зсув` для даних), тож ті самі байти можна дістати
через `hexdump -C -s OFFSET -n 64 /tmp/m0.img`.

## 6. Експерименти з пошкодженнями

Кожен збій, який інструмент має пережити, можна внести в *образи*
(ніколи — у живий пул) і прочитати назад:

```sh
# зіпсувати nvlist однієї мітки на члені 0 — scan має відкотитись на інші три
dd if=/dev/urandom of=/tmp/m0.img bs=1 count=64 seek=$((16*1024 + 200)) conv=notrunc
# зіпсувати блок даних на члені 0 — dump має вилікувати його з члена 1 і сказати про це
dd if=/dev/zero of=/tmp/m0.img bs=1 count=16 seek=$((4*1024*1024 + DVA_OFFSET)) conv=notrunc
```

`DVA_OFFSET` береться з рядка `[zio] read bp … dvas [vdev 0 off 0x…]`
попереднього запуску з `--debug`. Порівняйте вивід `--debug` до і після:
рядок `[zio]` для цього блоку має змінитися з `checksum Ok` на пристрої
#0 на `Mismatch`, а далі `Ok` на пристрої #1.

## 7. Що надсилати у звіті про помилку

`zvolrescue -f json -vv scan …`, `zvolrescue --debug-log trace.log …`
для команди, що впала, і відповідний вивід `zdb -l` / `zdb -e -p … -d`.
Жоден із них не містить даних тома; hex-дампи показують щонайбільше
64 байти блоку, що впав.
