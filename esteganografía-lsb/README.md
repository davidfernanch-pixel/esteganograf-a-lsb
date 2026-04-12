# UmbraSteg

Herramienta de esteganografía LSB (Least Significant Bit) con cifrado AES-GCM y compresión de datos. 
Todo el procesamiento se realiza de forma local en el navegador del usuario mediante Web Workers.

## Características
* Cifrado AES-GCM (Web Crypto API)
* Barajado pseudo-aleatorio de memoria eficiente (Lazy Shuffling)
* Explorador de planos de bits y análisis de entropía
* Sanitización de metadatos EXIF
