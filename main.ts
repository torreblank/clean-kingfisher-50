import { Application, Router } from "https://deno.land/x/oak@v12.6.1/mod.ts";
import { oakCors }      from "https://deno.land/x/cors@v1.2.2/mod.ts";
import * as OTPAuth     from "https://deno.land/x/otpauth@v9.1.4/dist/otpauth.esm.js"
import * as base32      from "https://deno.land/std/encoding/base32.ts";

import { Aes }          from "https://deno.land/x/crypto/aes.ts";
import { Cbc, Padding } from "https://deno.land/x/crypto/block-modes.ts";
import * as base64      from "https://deno.land/std/encoding/base64.ts";

const ISSUER = Deno.env.get("ISSUER")
const LLAVE  = Deno.env.get("LLAVE")

function encripta(texto: string) {
  const LLAVE = new TextEncoder("utf-8").encode("Contraseña123456").subarray(0,16);
  const iv = new Uint8Array(16);
  let data = new TextEncoder("utf-8").encode(texto);
  const cipher    = new Cbc(Aes, LLAVE, iv, Padding.PKCS7);
  const encrypted = cipher.encrypt(data);
  return base64.encode(encrypted) ;
}
function decripta(texto: string) {
  const LLAVE = new TextEncoder("utf-8").encode("Contraseña123456").subarray(0,16);
  const iv = new Uint8Array(16);
  const decipher  = new Cbc(Aes, LLAVE, iv, Padding.PKCS7);
  const encrypted = decipher.decrypt(base64.decode(texto));
  return new TextDecoder("utf-8").decode( encrypted ) ;
}

function creaTotp(user:string) {
  const llave = base32.encode(new TextEncoder("utf-8").encode( LLAVE+user ));
  let totp = new OTPAuth.TOTP({
    issuer: ISSUER, label: user, algorithm: "SHA1",
    digits: 6, period: 30, secret: llave
  });
  return totp
}
function validaToken(user:string, token_test:string) {
  const   totp = creaTotp(user);
  return (totp.validate({token: token_test, window: 1 }) !== null)
}
function tokenNow(user:string) {
  const  totp = creaTotp(user);
  return totp.generate();
}

const router = new Router();
router
  .get("/", (context) => {
    context.response.body = "[ API tutorial de JTK ]";
  })
  .get("/encripta/:enctxt", (context) => {
    if (context?.params?.enctxt) {
      const dectxt = decodeURIComponent(context.params.enctxt);
      context.response.body = encodeURIComponent( encripta(dectxt) );
    }
  })
  .get("/decripta/:enctxt", (context) => {
    if (context?.params?.enctxt) {
      const dectxt = decodeURIComponent(context.params.enctxt);
      context.response.body = encodeURIComponent( decripta(dectxt) );
    }
  })
  .get("/tokenahora/:user", (context) => {
    if (context?.params?.user) {
        context.response.body = tokenNow(context.params.user);
    }
  })  
  .get("/:user/:token", (context) => {
    if (context?.params?.token) {
      context.response.body = validaToken(context.params.user, context.params.token);
    }
  });

const app = new Application();
app.use(oakCors()); // Enable CORS for All Routes
app.use(router.routes());
app.use(router.allowedMethods());

await app.listen({ port: 8000 });
