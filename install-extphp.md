./configure --enable-zts --prefix=/opt/php-8.4.10 --enable-cli --with-openssl --with-password-argon2 --with-zlib --with-curl --enable-mbstring --enable-pcntl --enable-pdo --enable-sockets --with-zip --enable-shmop --with-pgsql --with-pdo-pgsql --with-bz2 --with-gmp --with-readline --with-config-file-path=/opt/php-8.4.10/etc --with-config-file-scan-dir=/opt/php-8.4.10/etc/conf.d LDFLAGS="-L/usr/local/lib" CFLAGS="-I/usr/local/include"

make clean
make -j$(nproc)
sudo make install
