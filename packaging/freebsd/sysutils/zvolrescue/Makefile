PORTNAME=	zvolrescue
DISTVERSIONPREFIX=	v
DISTVERSION=	0.9.9
CATEGORIES=	sysutils

MAINTAINER=	akapulko@gmail.com
COMMENT=	Read-only extraction of zvols and files from ZFS pools that no longer import
WWW=		https://github.com/click0/zvolrescue

LICENSE=	BSD3CLAUSE
LICENSE_FILE=	${WRKSRC}/LICENSE

USES=		cargo
USE_GITHUB=	yes
GH_ACCOUNT=	click0

# One workspace, five programs: each crate installed by its path.
CARGO_INSTALL_PATH=	crates/zvolrescue crates/zvoltimeline crates/zvolreport \
			crates/zvolcarve crates/zvolfiles

PROGRAMS=	zvolrescue zvoltimeline zvolreport zvolcarve zvolfiles
PLIST_FILES=	${PROGRAMS:S,^,bin/,} \
		${PROGRAMS:S,^,share/man/man1/,:S,$,.1.gz,}

post-install:
.for p in ${PROGRAMS}
	${INSTALL_MAN} ${WRKSRC}/man/${p}.1 ${STAGEDIR}${PREFIX}/share/man/man1/
.endfor

.include "${.CURDIR}/Makefile.crates"
.include <bsd.port.mk>
