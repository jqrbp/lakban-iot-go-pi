# lakban-iot-go-pi
Contoh tambal sulam kontrol perangkat keras lewat protokol tcp/ip.

======= FOLDER wemos-fw ==========

Dalam folder wemos-fw terdapat firmware untuk perangkat keras yang akan dikontrol melalui protokol tcp/ip.
Di sini kompilasi menggunakan plugin platformio dalam Microsoft Visual Code,
dengan spesifikasi: platform espressif8266 dengan board adalah d1_mini_lite.

Untuk penggunaan di board lain dengan sistem dasar esp8266, kompilasi dapat dilakukan dengan mengubah file platformio.ini,
terutama di bagian boards.
Keterangan lebih lengkap mengenai cara instalasi, konfigurasi, kompilasi, dan penulisan ke board dapat dilihat di situs ini:
http://docs.platformio.org/en/latest/platforms/espressif8266.html

Firmware wemos-fw sebenarnya hanyalah sebuah webserver yang menerima dan mengirimkan "http request / response".
Sebuah enkripsi aes sederhana juga ditambahkan untuk sedikit meningkatkan keamanan dalam proses transfer informasi dalam "http request / response" (tapi bukan berarti sudah benar-benar aman).

Konfigurasi:
1. Ganti nama ssid sesuai dengan ssid wifi yang tersedia.
2. Ganti password sesuai dengan password wifi yang diinginkan.
3. Ganti pin tglint (untuk koneksi ke pin input / button / switch).
4. Ganti pin ledint untuk koneksi ke pin output: LED atau relay, dll.

====== FOLDER wemos-cmd-go ==========

Dalam folder ini terdapat sebuah program sederhana dalam golang yang bisa digunakan untuk berinteraksi dengan firmware wemos-fw.
Kompilasinya dapat dilakukan lewat perintah "go build"
(program golang harus diinstal terlebih dahulu).

Cara penggunaan (setelah kompilasi):

wemos-cmd-go <set/get> <wemos-id> <iprange> <port> <cmd> <toggle>

Misal:

Set nilai 4 pin output (lihat pin tglint dalam wemos-fw) menjadi 0:
wemos-cmd-go set wemos-00 192.168.10 8088 0000
