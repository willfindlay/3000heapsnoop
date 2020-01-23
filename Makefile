USRBIN=/usr/bin
OPTDIR=/opt
INSTALLDIR=${OPTDIR}/3000heapsnoop

.PHONY: install

install:
	mkdir -p ${INSTALLDIR}
	cp -r ./* ${INSTALLDIR}
	ln -vsnf ${INSTALLDIR}/3000heapsnoop.py ${USRBIN}/3000heapsnoop
