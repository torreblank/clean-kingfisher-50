# REST API

A template of REST API app using Oak framework.
A partir del código demo, exploro funcionalidades para generar webhooks.
1) encriptado de un texto.
2) desencriptado.
3) generación de un TOTP.
4) validación de un token de TOTP.

Start the server with the command:
```
deno run --allow-net main.ts
```
This starts the server at http://localhost:8000/
Try go to http://localhost:8000/:usuario/:token
