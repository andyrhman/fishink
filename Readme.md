<p align="center">
  <a href="https://github.com/andyrhman/fishink.git" target="blank">
    <img src="https://i.imgur.com/1lhgc1O.png" width="200" alt="Fishink Logo" />
  </a>
</p>

<h1 align="center">Fishink Backend</h1>

<p align="center">
  Backend Django REST Framework untuk sistem deteksi URL phishing Fishink, termasuk integrasi model machine learning, website insight, riwayat sertifikat, dan screenshot website.
</p>

## Instalasi Playwright

Sebelum menjalankan server di wajibkan untuk menginstall chromium di playwright.

```bash
sudo apt-get update
sudo apt-get install -y \
  libnspr4 \
  libnss3 \
  libatk-bridge2.0-0t64 \
  libgtk-3-0t64 \
  libxkbcommon0 \
  libasound2t64 \
  libgbm1 \
  libx11-xcb1 \
  libdrm2 \
  libxcomposite1 \
  libxdamage1 \
  libxrandr2
python -m playwright install --with-deps chromium
```

## Tentang Project

Fishink Backend adalah layanan backend berbasis **Django REST Framework** yang menangani seluruh proses analisis URL untuk ekosistem Fishink.

Backend ini berperan sebagai pusat logika untuk:

- deteksi phishing URL menggunakan model machine learning,
- pengambilan informasi website seperti IP, lokasi, top level domain, dan certificate details,
- pengambilan riwayat sertifikat,
- pengambilan screenshot website,
- serta penyediaan API yang dipakai oleh frontend web dan nantinya ekstensi Chrome.

Project ini dikembangkan sebagai bagian dari sistem Fishink yang saya bangun dalam percakapan ini, dengan model phishing detection yang sudah diintegrasikan ke backend agar bisa dipakai langsung oleh frontend React maupun browser extension secara offline/terstruktur.

Karena project ini masih berada pada tahap **beta**, masih mungkin ada false positive, timeout pada website tertentu, atau penyesuaian logika pada beberapa endpoint.

## Fitur

- Deteksi phishing URL menggunakan model machine learning
- Endpoint informasi website (IP, lokasi, hosting provider, TLD, certificate details)
- Endpoint riwayat sertifikat website
- Endpoint screenshot website
- Integrasi model TensorFlow/Keras pada backend Django
- Whitelist trusted domain untuk mengurangi false positive
- API berbasis JSON menggunakan Django REST Framework
- Mendukung frontend React dan integrasi ekstensi Chrome
- Penyimpanan hasil dan konfigurasi melalui file model dan JSON pendukung

## Model Machine Learning

Backend ini menggunakan model phishing detection yang telah dilatih sebelumnya dan diintegrasikan ke Django melalui service layer.

Aset model yang dipakai:

* `wide_deep_fusion_20260403_075005.keras`
* `tokenizer_20260403_075005.pkl`
* `scaler_20260403_075005.pkl`
* `config_20260403_075005.json`

Model ini dipakai untuk:

* preprocessing URL,
* ekstraksi fitur struktural,
* tokenisasi URL,
* inferensi probabilitas phishing,
* dan pemetaan hasil menjadi `PHISHING` atau `AMAN`.

Selain itu, backend juga memiliki whitelist trusted domain untuk menekan false positive pada website populer dan terpercaya.

## Catatan Implementasi

* Backend ini dirancang untuk dipakai oleh frontend Fishink Web.
* Endpoint phishing check menggunakan model ML yang sudah diintegrasikan di backend.
* Endpoint screenshot memakai Playwright dan Cloudinary.
* Sebagian website bisa menghasilkan timeout atau gagal di-resolve, terutama website yang sudah mati, sangat lambat, atau diblokir jaringan.
* Whitelist trusted domain digunakan untuk membantu mengurangi false positive.

## Endpoint API

Phishing Check

```text
POST /api/phishing-check/
```

Contoh Request

```bash
curl -X POST http://127.0.0.1:8000/api/phishing-check/ \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

Contoh respons:

```json
{
  "success": true,
  "data": {
    "url": "https://example.com",
    "masked_url": "example.com",
    "probability": 0.12,
    "estimated_phishing_score": 12.0,
    "threshold": 0.05685228854417801,
    "prediction": "AMAN"
  }
}
