//! dRAID geometry (`vdev_draid.c`): distributed parity and spares over a
//! fixed permutation map. A block's columns are spread over the children
//! by a permutation row chosen from the block's logical offset; the
//! permutations are generated deterministically from a per-width seed and
//! verified against the checksum OpenZFS ships for each width, so the
//! layout computed here is exactly the one the kernel uses.
//!
//! Rows hand back [`crate::raidz::Map`]s: parity math and reconstruction
//! are the same as RAIDZ.

use crate::checksum::fletcher4;
use crate::raidz::{Column, Map};
use crate::Endian;

/// `VDEV_DRAID_ROWSHIFT` (`SPA_MAXBLOCKSHIFT`): a row is 16 MiB per child.
pub const ROWSHIFT: u32 = 24;
/// `VDEV_DRAID_ROWHEIGHT`.
pub const ROWHEIGHT: u64 = 1 << ROWSHIFT;
/// `VDEV_DRAID_SEED`, the fixed half of the permutation PRNG seed.
pub const SEED: u64 = 0xd_7a1d_5eed;
/// `VDEV_DRAID_MAXPARITY`.
pub const MAX_PARITY: u64 = 3;

/// `draid_maps[]`: (children, permutation rows, seed, fletcher4 word 0 of
/// the generated map) for every supported child count.
const MAPS: [(u64, u64, u64, u64); 254] = [
    // children, nperms, seed, fletcher4 checksum of the generated map
    (2, 256, 0x89ef3dabbcc7de37, 0x00000000433d433d),
    (3, 256, 0x89a57f3de98121b4, 0x00000000bcd8b7b5),
    (4, 256, 0xc9ea9ec82340c885, 0x00000001819d7c69),
    (5, 256, 0xf46733b7f4d47dfd, 0x00000002a1648d74),
    (6, 256, 0x88c3c62d8585b362, 0x00000003d3b0c2c4),
    (7, 256, 0x3a65d809b4d1b9d5, 0x000000055c4183ee),
    (8, 256, 0xe98930e3c5d2e90a, 0x00000006edfb0329),
    (9, 256, 0x5a5430036b982ccb, 0x00000008ceaf6934),
    (10, 256, 0x92bf389e9eadac74, 0x0000000b26668c09),
    (11, 256, 0x74ccebf1dcf3ae80, 0x0000000dd691358c),
    (12, 256, 0x8847e41a1a9f5671, 0x00000010a0c63c8e),
    (13, 256, 0x7481b56debf0e637, 0x0000001424121fe4),
    (14, 256, 0x559b8c44065f8967, 0x00000016ab2ff079),
    (15, 256, 0x34c49545a2ee7f01, 0x0000001a6028efd6),
    (16, 256, 0xb85f4fa81a7698f7, 0x0000001e95ff5e66),
    (17, 256, 0x6353e47b7e47aba0, 0x00000021a81fa0fe),
    (18, 256, 0xaa549746b1cbb81c, 0x00000026f02494c9),
    (19, 256, 0x892e343f2f31d690, 0x00000029eb392835),
    (20, 256, 0x76914824db98cc3f, 0x0000003004f31a7c),
    (21, 256, 0x4b3cbabf9cfb1d0f, 0x00000036363a2408),
    (22, 256, 0xf45c77abb4f035d4, 0x00000038dd0f3e84),
    (23, 256, 0x5e18bd7f3fd4baf4, 0x0000003f0660391f),
    (24, 256, 0xa7b3a4d285d6503b, 0x000000443dfc9ff6),
    (25, 256, 0x56ac7dd967521f5a, 0x0000004b03a87eb7),
    (26, 256, 0x3a42dfda4eb880f7, 0x000000522c719bba),
    (27, 256, 0xd200d2fc6b54bf60, 0x0000005760b4fdf5),
    (28, 256, 0xc52605bbd486c546, 0x0000005e00d8f74c),
    (29, 256, 0xc761779e63cd762f, 0x00000067be3cd85c),
    (30, 256, 0xca577b1e07f85ca5, 0x0000006f5517f3e4),
    (31, 256, 0xfd50a593c518b3d4, 0x0000007370e7778f),
    (32, 512, 0xc6c87ba5b042650b, 0x000000f7eb08a156),
    (33, 512, 0xc3880d0c9d458304, 0x0000010734b5d160),
    (34, 512, 0xe920927e4d8b2c97, 0x00000118c1edbce0),
    (35, 512, 0x8da7fcda87bde316, 0x0000012a3e9f9110),
    (36, 512, 0xcf09937491514a29, 0x0000013bd6a24bef),
    (37, 512, 0x9b5abbf345cbd7cc, 0x0000014b9d90fac3),
    (38, 512, 0x506312a44668d6a9, 0x0000015e1b5f6148),
    (39, 512, 0x71659ede62b4755f, 0x00000173ef029bcd),
    (40, 512, 0xa7fde73fb74cf2d7, 0x000001866fb72748),
    (41, 512, 0x19e8b461a1dea1d3, 0x000001a046f76b23),
    (42, 512, 0x031c9b868cc3e976, 0x000001afa64c49d3),
    (43, 512, 0xbaa5125faa781854, 0x000001c76789e278),
    (44, 512, 0x4ed55052550d721b, 0x000001d800ccd8eb),
    (45, 512, 0x0fd63ddbdff90677, 0x000001f08ad59ed2),
    (46, 512, 0x36d66546de7fdd6f, 0x000002016f09574b),
    (47, 512, 0x99f997e7eafb69d7, 0x0000021e42e47cb6),
    (48, 512, 0xbecd9c2571312c5d, 0x000002320fe2872b),
    (49, 512, 0xd97371329e488a32, 0x0000024cd73f2ca7),
    (50, 512, 0x30e9b136670749ee, 0x000002681c83b0e0),
    (51, 512, 0x11ad6bc8f47aaeb4, 0x0000027e9261b5d5),
    (52, 512, 0x68e445300af432c1, 0x0000029aa0eb7dbf),
    (53, 512, 0x910fb561657ea98c, 0x000002b3dca04853),
    (54, 512, 0xd619693d8ce5e7a5, 0x000002cc280e9c97),
    (55, 512, 0x24e281f564dbb60a, 0x000002e9fa842713),
    (56, 512, 0x947a7d3bdaab44c5, 0x000003046680f72e),
    (57, 512, 0x2d44fec9c093e0de, 0x00000324198ba810),
    (58, 512, 0x87743c272d29bb4c, 0x0000033ec48c9ac9),
    (59, 512, 0x96aa3b6f67f5d923, 0x0000034faead902c),
    (60, 512, 0x94a4f1faf520b0d3, 0x0000037d713ab005),
    (61, 512, 0xb13ed3a272f711a2, 0x00000397368f3cbd),
    (62, 512, 0x3b1b11805fa4a64a, 0x000003b8a5e2840c),
    (63, 512, 0x4c74caad9172ba71, 0x000003d4be280290),
    (64, 512, 0x035ff643923dd29e, 0x000003fad6c355e1),
    (65, 512, 0x768e9171b11abd3c, 0x0000040eb07fed20),
    (66, 512, 0x75880e6f78a13ddd, 0x000004433d6acf14),
    (67, 512, 0x910b9714f698a877, 0x00000451ea65d5db),
    (68, 512, 0x87f5db6f9fdcf5c7, 0x000004732169e3f7),
    (69, 512, 0x836d4968fbaa3706, 0x000004954068a380),
    (70, 512, 0xc567d73a036421ab, 0x000004bd7cb7bd3d),
    (71, 512, 0x619df40f240b8fed, 0x000004e376c2e972),
    (72, 512, 0x42763a680d5bed8e, 0x000005084275c680),
    (73, 512, 0x5866f064b3230431, 0x0000052906f2c9ab),
    (74, 512, 0x9fa08548b1621a44, 0x0000054708019247),
    (75, 512, 0xb6053078ce0fc303, 0x00000572cc5c72b0),
    (76, 512, 0x4a7aad7bf3890923, 0x0000058e987bc8e9),
    (77, 512, 0xe165613fd75b5a53, 0x000005c20473a211),
    (78, 512, 0x3ff154ac878163a6, 0x000005d659194bf3),
    (79, 512, 0x24b93ade0aa8a532, 0x0000060a201c4f8e),
    (80, 512, 0xc18e2d14cd9bb554, 0x0000062c55cfe48c),
    (81, 512, 0x98cc78302feb58b6, 0x0000066656a07194),
    (82, 512, 0xc6c5fd5a2abc0543, 0x0000067cff94fbf8),
    (83, 512, 0xa7962f514acbba21, 0x000006ab7b5afa2e),
    (84, 512, 0xba02545069ddc6dc, 0x000006d19861364f),
    (85, 512, 0x447c73192c35073e, 0x000006fce315ce35),
    (86, 512, 0x48beef9e2d42b0c2, 0x00000720a8e38b6b),
    (87, 512, 0x4874cf98541a35e0, 0x00000758382a2273),
    (88, 512, 0xad4cf8333a31127a, 0x00000781e1651b1b),
    (89, 512, 0x47ae4859d57888c1, 0x000007b27edbe5bc),
    (90, 512, 0x06f7723cfe5d1891, 0x000007dc2a96d8eb),
    (91, 512, 0xd4e44218d660576d, 0x0000080ac46f02d5),
    (92, 512, 0x7066702b0d5be1f2, 0x00000832c96d154e),
    (93, 512, 0x011209b4f9e11fb9, 0x0000085eefda104c),
    (94, 512, 0x47ffba30a0b35708, 0x00000899badc32dc),
    (95, 512, 0x1a95a6ac4538aaa8, 0x000008b6b69a42b2),
    (96, 512, 0xbda2b239bb2008eb, 0x000008f22d2de38a),
    (97, 512, 0x7ffa0bea90355c6c, 0x0000092e5b23b816),
    (98, 512, 0x1d56ba34be426795, 0x0000094f482e5d1b),
    (99, 512, 0x0aa89d45c502e93d, 0x00000977d94a98ce),
    (100, 512, 0x54369449f6857774, 0x000009c06c9b34cc),
    (101, 512, 0xf7d4dd8445b46765, 0x000009e5dc542259),
    (102, 512, 0xfa8866312f169469, 0x00000a16b54eae93),
    (103, 512, 0xd8a5aea08aef3ff9, 0x00000a381d2cbfe7),
    (104, 512, 0x66bcd2c3d5f9ef0e, 0x00000a8191817be7),
    (105, 512, 0x3fb13a47a012ec81, 0x00000ab562b9a254),
    (106, 512, 0x43100f01c9e5e3ca, 0x00000aeee84c185f),
    (107, 512, 0xca09c50ccee2d054, 0x00000b1c359c047d),
    (108, 512, 0xd7176732ac503f9b, 0x00000b578bc52a73),
    (109, 512, 0xed206e51f8d9422d, 0x00000b8083e0d960),
    (110, 512, 0x17ead5dc6ba0dcd6, 0x00000bcfb1a32ca8),
    (111, 512, 0x5f1dc21e38a969eb, 0x00000c0171becdd6),
    (112, 512, 0xddaa973de33ec528, 0x00000c3edaba4b95),
    (113, 512, 0x2a5eccd7735a3630, 0x00000c630664e7df),
    (114, 512, 0xafcccee5c0b71446, 0x00000cb65392f6e4),
    (115, 512, 0x8fa30c5e7b147e27, 0x00000cd4db391e55),
    (116, 512, 0x5afe0711fdfafd82, 0x00000d08cb4ec35d),
    (117, 512, 0x533a6090238afd4c, 0x00000d336f115d1b),
    (118, 512, 0x90cf11b595e39a84, 0x00000d8e041c2048),
    (119, 512, 0x0d61a3b809444009, 0x00000dcb798afe35),
    (120, 512, 0x7f34da0f54b0d114, 0x00000df3922664e1),
    (121, 512, 0xa52258d5b72f6551, 0x00000e4d37a9872d),
    (122, 512, 0xc1de54d7672878db, 0x00000e6583a94cf6),
    (123, 512, 0x1d03354316a414ab, 0x00000ebffc50308d),
    (124, 512, 0xcebdcc377665412c, 0x00000edee1997cea),
    (125, 512, 0x4ddd4c04b1a12344, 0x00000f21d64b373f),
    (126, 512, 0x64fc8f94e3973658, 0x00000f8f87a8896b),
    (127, 512, 0x68765f78034a334e, 0x00000fb8fe62197e),
    (128, 512, 0xaf36b871a303e816, 0x00000fec6f3afb1e),
    (129, 512, 0x2a4cbf73866c3a28, 0x00001027febfe4e5),
    (130, 512, 0x9cb128aacdcd3b2f, 0x0000106aa8ac569d),
    (131, 512, 0x5511d41c55869124, 0x000010bbd755ddf1),
    (132, 512, 0x42f92461937f284a, 0x000010fb8bceb3b5),
    (133, 512, 0xe2d89a1cf6f1f287, 0x0000114cf5331e34),
    (134, 512, 0xdc631a038956200e, 0x0000116428d2adc5),
    (135, 512, 0xb2e5ac222cd236be, 0x000011ca88e4d4d2),
    (136, 512, 0xbc7d8236655d88e7, 0x000011e39cb94e66),
    (137, 512, 0x073e02d88d2d8e75, 0x0000123136c7933c),
    (138, 512, 0x3ddb9c3873166be0, 0x00001280e4ec6d52),
    (139, 512, 0x7d3b1a845420e1b5, 0x000012c2e7cd6a44),
    (140, 512, 0x60102308aa7b2a6c, 0x000012fc490e6c7d),
    (141, 512, 0xdb22bb2f9eb894aa, 0x00001343f5a85a1a),
    (142, 512, 0xd853f879a13b1606, 0x000013bb7d5f9048),
    (143, 512, 0x001620a03f804b1d, 0x000013e74cc794fd),
    (144, 512, 0xfdb52dda76fbf667, 0x00001442d2f22480),
    (145, 512, 0xa9160110f66e24ff, 0x0000144b899f9dbb),
    (146, 512, 0x77306a30379ae03b, 0x000014cb98eb1f81),
    (147, 512, 0x14f5985d2752319d, 0x000014feab821fc9),
    (148, 512, 0xa4b8ff11de7863f8, 0x0000154a0e60b9c9),
    (149, 512, 0x44b345426455c1b3, 0x000015999c3c569c),
    (150, 512, 0x272677826049b46c, 0x000015c9697f4b92),
    (151, 512, 0x2f9216e2cd74fe40, 0x0000162b1f7bbd39),
    (152, 512, 0x706ae3e763ad8771, 0x00001661371c55e1),
    (153, 512, 0xf7fd345307c2480e, 0x000016e251f28b6a),
    (154, 512, 0x6e94e3d26b3139eb, 0x000016f2429bb8c6),
    (155, 512, 0x5458bbfbb781fcba, 0x0000173efdeca1b9),
    (156, 512, 0xa80e2afeccd93b33, 0x000017bfdcb78adc),
    (157, 512, 0x1e4ccbb22796cf9d, 0x00001826fdcc39c9),
    (158, 512, 0x8fba4b676aaa3663, 0x00001841a1379480),
    (159, 512, 0xf82b843814b315fa, 0x000018886e19b8a3),
    (160, 512, 0x7f21e920ecf753a3, 0x0000191812ca0ea7),
    (161, 512, 0x48bb8ea2c4caa620, 0x0000192f310faccf),
    (162, 512, 0x5cdb652b4952c91b, 0x0000199e1d7437c7),
    (163, 512, 0x6ac1ba6f78c06cd4, 0x000019cd11f82c70),
    (164, 512, 0x9faf5f9ca2669a56, 0x00001a18d5431f6a),
    (165, 512, 0xaa57e9383eb01194, 0x00001a9e7d253d85),
    (166, 512, 0x896967bf495c34d2, 0x00001afb8319b9fc),
    (167, 512, 0xdfad5f05de225f1b, 0x00001b3a59c3093b),
    (168, 512, 0xfd299a99f9f2abdd, 0x00001bb6f1a10799),
    (169, 512, 0xdda239e798fe9fd4, 0x00001bfae0c9692d),
    (170, 512, 0x5fca670414a32c3e, 0x00001c22129dbcff),
    (171, 512, 0x1bb8934314b087de, 0x00001c955db36cd0),
    (172, 512, 0xd96394b4b082200d, 0x00001cfc8619b7e6),
    (173, 512, 0xb612a7735b1c8cbc, 0x00001d303acdd585),
    (174, 512, 0x28e7430fe5875fe1, 0x00001d7ed5b3697d),
    (175, 512, 0x5038e89efdd981b9, 0x00001dc40ec35c59),
    (176, 512, 0x075fd78f1d14db7c, 0x00001e31c83b4a2b),
    (177, 512, 0xc50fafdb5021be15, 0x00001e7cdac82fbc),
    (178, 512, 0xe6dc7572ce7b91c7, 0x00001edd8bb454fc),
    (179, 512, 0x21f7843e7beda537, 0x00001f3a8e019d6c),
    (180, 512, 0xc83385e20b43ec82, 0x00001f70735ec137),
    (181, 512, 0xca818217dddb21fd, 0x0000201ca44c5a3c),
    (182, 512, 0xe6035defea48f933, 0x00002038e3346658),
    (183, 512, 0x47262a4f953dac5a, 0x000020c2e554314e),
    (184, 512, 0xe24c7246260873ea, 0x000021197e618d64),
    (185, 512, 0xeef6b57c9b58e9e1, 0x0000217ea48ecddc),
    (186, 512, 0x2becd3346e386142, 0x000021c496d4a5f9),
    (187, 512, 0x63c6207bdf3b40a3, 0x0000220e0f2eec0c),
    (188, 512, 0x3056ce8989767d4b, 0x0000228eb76cd137),
    (189, 512, 0x91af61c307cee780, 0x000022e17e2ea501),
    (190, 512, 0xda359da225f6d54f, 0x00002358a2debc19),
    (191, 512, 0x0a5f7a2a55607ba0, 0x0000238a79dac18c),
    (192, 512, 0x27bb75bf5224638a, 0x00002403a58e2351),
    (193, 512, 0x1ebfdb94630f5d0f, 0x00002492a10cb339),
    (194, 512, 0x6eae5e51d9c5f6fb, 0x000024ce4bf98715),
    (195, 512, 0x08d903b4daedc2e0, 0x0000250d1e15886c),
    (196, 512, 0xc722a2f7fa7cd686, 0x0000258a99ed0c9e),
    (197, 512, 0x8f71faf0e54e361d, 0x000025dee11976f5),
    (198, 512, 0x87f64695c91a54e7, 0x0000264e00a43da0),
    (199, 512, 0xc719cbac2c336b92, 0x000026d327277ac1),
    (200, 512, 0xe7e647afaf771ade, 0x000027523a5c44bf),
    (201, 512, 0x12d4b5c38ce8c946, 0x0000273898432545),
    (202, 512, 0xf2e0cd4067bdc94a, 0x000027e47bb2c935),
    (203, 512, 0x21b79f14d6d947d3, 0x0000281e64977f0d),
    (204, 512, 0x515093f952f18cd6, 0x0000289691a473fd),
    (205, 512, 0xd47b160a1b1022c8, 0x00002903e8b52411),
    (206, 512, 0xc02fc96684715a16, 0x0000297515608601),
    (207, 512, 0xef51e68efba72ed0, 0x000029ef73604804),
    (208, 512, 0x9e3be6e5448b4f33, 0x00002a2846ed074b),
    (209, 512, 0x81d446c6d5fec063, 0x00002a92ca693455),
    (210, 512, 0xff215de8224e57d5, 0x00002b2271fe3729),
    (211, 512, 0xe2524d9ba8f69796, 0x00002b64b99c3ba2),
    (212, 512, 0xf6b28e26097b7e4b, 0x00002bd768b6e068),
    (213, 512, 0x893a487f30ce1644, 0x00002c67f722b4b2),
    (214, 512, 0x386566c3fc9871df, 0x00002cc1cf8b4037),
    (215, 512, 0x1e0ed78edf1f558a, 0x00002d3948d36c7f),
    (216, 512, 0xe3bc20c31e61f113, 0x00002d6d6b12e025),
    (217, 512, 0xd6c3ad2e23021882, 0x00002deff7572241),
    (218, 512, 0xb4a9f95cf0f69c5a, 0x00002e67d537aa36),
    (219, 512, 0x6e98ed6f6c38e82f, 0x00002e9720626789),
    (220, 512, 0x2e01edba33fddac7, 0x00002f407c6b0198),
    (221, 512, 0x559d02e1f5f57ccc, 0x00002fb6a5ab4f24),
    (222, 512, 0xac18f5a916adcd8e, 0x0000304ae1c5c57e),
    (223, 512, 0x15789fbaddb86f4b, 0x0000306f6e019c78),
    (224, 512, 0xf4a9c36d5bc4c408, 0x000030da40434213),
    (225, 512, 0xf640f90fd2727f44, 0x00003189ed37b90c),
    (226, 512, 0xb5313d390d61884a, 0x000031e152616b37),
    (227, 512, 0x4bae6b3ce9160939, 0x0000321f40aeac42),
    (228, 512, 0x838c34480f1a66a1, 0x000032f389c0f78e),
    (229, 512, 0xb1c4a52c8e3d6060, 0x0000330062a40284),
    (230, 512, 0xe0f1110c6d0ed822, 0x0000338be435644f),
    (231, 512, 0x9f1a8ccdcea68d4b, 0x000034045a4e97e1),
    (232, 512, 0x3261ed62223f3099, 0x000034702cfc401c),
    (233, 512, 0xf2191e2311022d65, 0x00003509dd19c9fc),
    (234, 512, 0xf102a395c2033abc, 0x000035654dc96fae),
    (235, 512, 0x11fe378f027906b6, 0x000035b5193b0264),
    (236, 512, 0xf777f2c026b337aa, 0x000036704f5d9297),
    (237, 512, 0x1b04e9c2ee143f32, 0x000036dfbb7af218),
    (238, 512, 0x2fcec95266f9352c, 0x00003785c8df24a9),
    (239, 512, 0xfe2b0e47e427dd85, 0x000037cbdf5da729),
    (240, 512, 0x72b49bf2225f6c6d, 0x0000382227c15855),
    (241, 512, 0x50486b43df7df9c7, 0x0000389b88be6453),
    (242, 512, 0x5192a3e53181c8ab, 0x000038ddf3d67263),
    (243, 512, 0xe9f5d8365296fd5e, 0x0000399f1c6c9e9c),
    (244, 512, 0xc740263f0301efa8, 0x00003a147146512d),
    (245, 512, 0x23cd0f2b5671e67d, 0x00003ab10bcc0d9d),
    (246, 512, 0x002ccc7e5cd41390, 0x00003ad6cd14a6c0),
    (247, 512, 0x9aafb3c02544b31b, 0x00003b8cb8779fb0),
    (248, 512, 0x72ba07a78b121999, 0x00003c24142a5a3f),
    (249, 512, 0x3d784aa58edfc7b4, 0x00003cd084817d99),
    (250, 512, 0xaab750424d8004af, 0x00003d506a8e098e),
    (251, 512, 0x84403fcf8e6b5ca2, 0x00003d4c54c2aec4),
    (252, 512, 0x71eb7455ec98e207, 0x00003e655715cf2c),
    (253, 512, 0xd752b4f19301595b, 0x00003ecd7b2ca5ac),
    (254, 512, 0xc4674129750499de, 0x00003e99e86d3e95),
    (255, 512, 0x9772baff5cd12ef5, 0x00003f895c019841),
];

/// `vdev_draid_rand`: xoroshiro128** style generator over a 2-word state.
pub fn rand(s: &mut [u64; 2]) -> u64 {
    let s0 = s[0];
    let mut s1 = s[1];
    let result = s0.wrapping_add(s1).rotate_left(17).wrapping_add(s0);
    s1 ^= s0;
    s[0] = s0.rotate_left(49) ^ s1 ^ (s1 << 21);
    s[1] = s1.rotate_left(28);
    result
}

/// Why a dRAID configuration cannot be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DraidError {
    /// No permutation map for this many children (2..=255).
    NoMap(u64),
    /// Data, parity and spare counts do not fit the child count.
    Geometry(String),
    /// The generated permutations do not match OpenZFS's checksum.
    MapChecksum {
        /// Children.
        children: u64,
        /// Expected fletcher4 word 0.
        expected: u64,
        /// What was generated.
        got: u64,
    },
}

impl std::fmt::Display for DraidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DraidError::NoMap(c) => write!(f, "no dRAID permutation map for {c} children"),
            DraidError::Geometry(s) => write!(f, "dRAID geometry: {s}"),
            DraidError::MapChecksum {
                children,
                expected,
                got,
            } => write!(
                f,
                "dRAID permutation map for {children} children has checksum {got:#x}, expected {expected:#x}"
            ),
        }
    }
}

/// `vdev_draid_generate_perms`: `nperms` rows of `children` entries, each
/// row a Fisher–Yates shuffle of the previous one driven by [`rand`].
pub fn generate_perms(children: u64, nperms: u64, seed: u64) -> Vec<u8> {
    let n = children as usize;
    let mut perms = vec![0u8; n * nperms as usize];
    let mut previous: Vec<u8> = (0..children as u8).collect();
    let mut state = [SEED, seed];
    for i in 0..nperms as usize {
        let row = &mut perms[i * n..(i + 1) * n];
        row.copy_from_slice(&previous);
        for j in (1..n).rev() {
            let k = (rand(&mut state) % (j as u64 + 1)) as usize;
            row.swap(j, k);
        }
        previous.copy_from_slice(row);
    }
    perms
}

/// `vdev_draid_config_t`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// `draid_ndata`: data columns per group.
    pub ndata: u64,
    /// `nparity`.
    pub nparity: u64,
    /// `draid_nspares`: distributed spares.
    pub nspares: u64,
    /// Children of the vdev.
    pub children: u64,
    /// `draid_ngroups`: groups per slice.
    pub ngroups: u64,
    /// Permutation rows.
    pub nperms: u64,
    /// `nperms * children` child indices.
    pub perms: Vec<u8>,
    /// `ndata + nparity`.
    pub groupwidth: u64,
    /// `children - nspares`.
    pub ndisks: u64,
    /// `groupwidth * ROWHEIGHT`.
    pub groupsz: u64,
    /// `(groupsz * ngroups) / ndisks`.
    pub devslicesz: u64,
}

impl Config {
    /// Build and verify the configuration (`vdev_draid_init`).
    pub fn new(
        ndata: u64,
        nparity: u64,
        nspares: u64,
        children: u64,
        ngroups: u64,
    ) -> Result<Config, DraidError> {
        if nparity == 0 || nparity > MAX_PARITY {
            return Err(DraidError::Geometry(format!("nparity {nparity}")));
        }
        if ngroups == 0 || children < ndata + nparity + nspares || ndata == 0 {
            return Err(DraidError::Geometry(format!(
                "ndata {ndata} + nparity {nparity} + nspares {nspares} does not fit {children} children (ngroups {ngroups})"
            )));
        }
        let &(_, nperms, seed, checksum) = MAPS
            .iter()
            .find(|m| m.0 == children)
            .ok_or(DraidError::NoMap(children))?;
        let perms = generate_perms(children, nperms, seed);
        let got = fletcher4(&perms, Endian::Little)[0];
        if got != checksum {
            return Err(DraidError::MapChecksum {
                children,
                expected: checksum,
                got,
            });
        }
        let groupwidth = ndata + nparity;
        let ndisks = children - nspares;
        if groupwidth > ndisks || (groupwidth * ngroups) % ndisks != 0 {
            return Err(DraidError::Geometry(format!(
                "groupwidth {groupwidth}, ndisks {ndisks}, ngroups {ngroups}"
            )));
        }
        let groupsz = groupwidth * ROWHEIGHT;
        Ok(Config {
            ndata,
            nparity,
            nspares,
            children,
            ngroups,
            nperms,
            perms,
            groupwidth,
            ndisks,
            groupsz,
            devslicesz: (groupsz * ngroups) / ndisks,
        })
    }

    /// `vdev_draid_get_perm` + `vdev_draid_permute_id`: the child that
    /// holds logical column `index` of permutation `pindex`.
    pub fn permute(&self, pindex: u64, index: u64) -> u64 {
        let ncols = self.children;
        let poff = pindex % (self.nperms * ncols);
        let base = &self.perms[((poff / ncols) * ncols) as usize..];
        let iter = poff % ncols;
        (u64::from(base[index as usize]) + iter) % ncols
    }

    /// `vdev_draid_asize`: bytes allocated for `psize` bytes of data.
    pub fn asize(&self, psize: u64, ashift: u32) -> u64 {
        let rows = (psize - 1) / (self.ndata << ashift) + 1;
        (rows * self.groupwidth) << ashift
    }

    /// `vdev_draid_asize_to_psize`.
    pub fn asize_to_psize(&self, asize: u64) -> u64 {
        (asize / self.groupwidth) * self.ndata
    }

    /// `vdev_draid_logical_to_physical`: child-relative byte offset of the
    /// row holding `logical`, with the permutation index and the first
    /// column's position in it.
    pub fn logical_to_physical(&self, logical: u64, ashift: u32) -> (u64, u64, u64) {
        let rowheight_sectors = ROWHEIGHT >> ashift;
        let group = logical / self.groupsz;
        let groupstart = (group * self.groupwidth) % self.ndisks;
        let b_offset = (logical >> ashift) % (rowheight_sectors * self.groupwidth);
        let perm = group / self.ngroups;
        let row = perm * ((self.groupwidth * self.ngroups) / self.ndisks)
            + ((group % self.ngroups) * self.groupwidth) / self.ndisks;
        (
            (rowheight_sectors * row + b_offset / self.groupwidth) << ashift,
            perm,
            groupstart,
        )
    }

    /// One row (`vdev_draid_map_alloc_row`) for `io_size` bytes at
    /// logical `io_offset`, which must not cross a group boundary.
    fn row(&self, io_offset: u64, io_size: u64, ashift: u32) -> Map {
        let (mut physical, perm, groupstart) = self.logical_to_physical(io_offset, ashift);
        let wrap = if groupstart + self.groupwidth > self.ndisks {
            self.ndisks - groupstart
        } else {
            self.groupwidth
        };
        let psize = io_size >> ashift;
        let q = psize / self.ndata;
        let r = psize - q * self.ndata;
        let bc = if r == 0 { 0 } else { r + self.nparity };
        let tot = psize + self.nparity * (q + u64::from(r != 0));
        let mut cols = Vec::with_capacity(self.groupwidth as usize);
        for i in 0..self.groupwidth {
            let c = (groupstart + i) % self.ndisks;
            if i == wrap {
                physical += ROWHEIGHT;
            }
            let size = if q == 0 && i >= bc {
                0
            } else if i < bc {
                (q + 1) << ashift
            } else {
                q << ashift
            };
            cols.push(Column {
                devidx: self.permute(perm, c),
                offset: physical,
                size,
            });
        }
        // Unlike RAIDZ, parity is generated over every column of the
        // row (rr_cols == groupwidth): the zero-length trailing columns of
        // a short row still shift the Q/R Horner evaluation, so they stay
        // part of data().
        Map {
            cols,
            nparity: self.nparity as usize,
            acols: self.groupwidth as usize,
            bigcols: bc as usize,
            asize: tot << ashift,
            nskip: tot.div_ceil(self.groupwidth) * self.groupwidth - tot,
        }
    }

    /// `vdev_draid_map_alloc`: the one or two rows holding `psize` bytes
    /// (a multiple of `1 << ashift`) at top-level offset `offset`; a block
    /// that crosses a group boundary continues in the next group.
    pub fn map(&self, offset: u64, psize: u64, ashift: u32) -> Vec<Map> {
        let mut io_size = psize;
        let group = offset / self.groupsz;
        let next_group = (group + 1) * self.groupsz;
        if offset + self.asize(psize, ashift) > next_group {
            io_size = self.asize_to_psize(next_group - offset);
        }
        let mut rows = vec![self.row(offset, io_size, ashift)];
        if io_size < psize {
            rows.push(self.row(
                offset + self.asize(io_size, ashift),
                psize - io_size,
                ashift,
            ));
        }
        rows
    }

    /// `vdev_draid_spare_get_child`: the child that distributed spare
    /// `spare_id` stands for at child-relative `physical_offset`.
    pub fn spare_child(&self, spare_id: u64, physical_offset: u64) -> u64 {
        let perm = physical_offset / self.devslicesz;
        self.permute(perm, (self.children - 1) - spare_id)
    }
}

/// Parse the spare index out of a distributed spare name such as
/// `draid1-0-2` (`draid<parity>-<top vdev id>-<spare id>`).
pub fn spare_id_from_name(name: &str) -> Option<u64> {
    name.rsplit('-').next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_shipped_map_regenerates_with_its_checksum() {
        // The table's checksums are OpenZFS's own oracle for the PRNG and
        // the shuffle: one wrong rotation and none of these match.
        for &(children, nperms, seed, checksum) in MAPS.iter() {
            let perms = generate_perms(children, nperms, seed);
            assert_eq!(
                fletcher4(&perms, Endian::Little)[0],
                checksum,
                "children {children}"
            );
            // Every row is a permutation.
            for row in perms.chunks(children as usize) {
                let mut seen = vec![false; children as usize];
                for &v in row {
                    assert!(!seen[v as usize]);
                    seen[v as usize] = true;
                }
            }
        }
    }

    #[test]
    fn geometry_and_rows() {
        // draid1:4d:6c:1s (ztest's default shape).
        let cfg = Config::new(4, 1, 1, 6, 1).unwrap();
        assert_eq!((cfg.groupwidth, cfg.ndisks, cfg.groupsz), (5, 5, 5 << 24));
        assert_eq!(cfg.devslicesz, 1 << 24);
        assert_eq!(cfg.asize(4096, 12), 5 * 4096);
        assert_eq!(cfg.asize(16384, 12), 5 * 4096);
        assert_eq!(cfg.asize(20480, 12), 10 * 4096);
        let rows = cfg.map(0, 4096, 12);
        assert_eq!(rows.len(), 1);
        let m = &rows[0];
        assert_eq!((m.nparity, m.acols, m.bigcols), (1, 5, 2));
        assert_eq!(m.cols.len(), 5);
        assert_eq!(m.data().len(), 4);
        assert!(m.cols[..2].iter().all(|c| c.size == 4096));
        assert!(m.cols[2..].iter().all(|c| c.size == 0));
        // All columns of a row sit at the same child offset and on
        // distinct children.
        let mut devs: Vec<u64> = m.cols.iter().map(|c| c.devidx).collect();
        devs.sort_unstable();
        devs.dedup();
        assert_eq!(devs.len(), 5);
        assert!(m.cols.iter().all(|c| c.offset == 0));
        // A full stripe: four data sectors and one parity sector.
        let m = &cfg.map(5 * 4096, 16384, 12)[0];
        assert_eq!((m.acols, m.bigcols, m.nskip), (5, 0, 0));
        assert!(m.cols.iter().all(|c| c.size == 4096 && c.offset == 4096));
        // A block that crosses the group boundary spans two rows.
        let near_end = cfg.groupsz - 5 * 4096;
        let rows = cfg.map(near_end, 32768, 12);
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0].data().iter().map(|c| c.size).sum::<u64>()
                + rows[1].data().iter().map(|c| c.size).sum::<u64>(),
            32768
        );
        assert_eq!(spare_id_from_name("draid1-0-2"), Some(2));
        assert!(Config::new(4, 1, 1, 5, 1).is_err());
        assert!(matches!(
            Config::new(4, 1, 1, 300, 1),
            Err(DraidError::NoMap(300))
        ));
    }
}
