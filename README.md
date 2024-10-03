# floodergo
rewrite flooder into go

how to install 
```bash
- git clone https://github.com/whitehat57/floodergo.git
- cd floodergo
- go mod init floodergo.go
- go mod tidy
- go build floodergo.go
- rm go.mod
- rm go.sum
- rm floodergo.go
- ./floodergo
```
# harus sudah install golang minimal versi 1.22.0

Untuk menginstal Golang versi terbaru di Termux, ikuti langkah-langkah berikut:

- Perbarui Termux: Pastikan Termux kamu up to date dengan menjalankan perintah berikut:
``` bash
pkg update && pkg upgrade
```
- Install Golang: Gunakan perintah berikut untuk menginstal Golang versi terbaru dari repositori resmi Termux:
``` bash
pkg install golang
```
- Cek Versi Golang: Setelah proses instalasi selesai, pastikan Golang terinstal dengan benar dan cek versi yang diinstal:
```bash
go version
```
- Atur Path (Opsional jika diperlukan): Jika kamu memerlukan path khusus untuk Go workspace atau binari, kamu dapat menambahkannya ke .bashrc atau .zshrc kamu:
```bash
export GOPATH=$HOME/go
export PATH=$PATH:$GOROOT/bin:$GOPATH/bin
```
- Setelah menambahkan, jalankan perintah berikut untuk menerapkan perubahan:
```bash
source ~/.bashrc
```

Instal Golang versi terbaru di Ubuntu / VPS, kamu bisa mengikuti langkah berikut:

1. Unduh Golang Versi Terbaru (Misalnya 1.23)
Kunjungi halaman unduhan Golang dan temukan tautan untuk Golang versi terbaru. Jika versi 1.23 sudah dirilis, unduh dengan perintah seperti ini (ganti 1.23 dengan versi yang sesuai):
```bash
wget https://go.dev/dl/go1.23.2.linux-amd64.tar.gz
```
2. Ekstrak dan Install
Setelah diunduh, ekstrak file tarball ke /usr/local:
```bash
sudo tar -C /usr/local -xzf go1.23.2.linux-amd64.tar.gz
```
3. Atur PATH
Tambahkan direktori bin Go ke PATH di .profile atau .bashrc:
```bash
export PATH=$PATH:/usr/local/go/bin
```
Jalankan source ~/.profile atau source ~/.bashrc untuk menerapkan perubahan.

4. Cek Instalasi
Periksa versi Go yang terinstal dengan menjalankan:
```bash
go version
```
