cd dist
mkdir -p libapache2-mod-evasive/usr/lib/apache2/modules
cp /usr/lib/apache2/modules/mod_evasive.so libapache2-mod-evasive/usr/lib/apache2/modules
dpkg-deb --build libapache2-mod-evasive
