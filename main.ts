import { Application, Router } from "https://deno.land/x/oak@v12.6.1/mod.ts";
import { oakCors }      from "https://deno.land/x/cors@v1.2.2/mod.ts";
import * as OTPAuth     from "https://deno.land/x/otpauth@v9.1.4/dist/otpauth.esm.js"
import * as base32      from "https://deno.land/std/encoding/base32.ts";

import { Aes }          from "https://deno.land/x/crypto/aes.ts";
import { Cbc, Padding } from "https://deno.land/x/crypto/block-modes.ts";
import * as base64      from "https://deno.land/std/encoding/base64.ts";

const ISSUER    = Deno.env.get("ISSUER")
const LLAVE     = Deno.env.get("LLAVE")
const LLAVECRYP = Deno.env.get("LLAVECRYP")

function encripta(texto:string, arr_size=16) {
  const LLAVE     = new TextEncoder().encode(LLAVECRYP).subarray(0,arr_size);
  const iv        = new Uint8Array(arr_size);
  let data        = new TextEncoder().encode(texto);
  const cipher    = new Cbc(Aes, LLAVE, iv, Padding.PKCS7);
  const encrypted = cipher.encrypt(data);
  return base64.encode(encrypted) ;
}
function decripta(texto: string, arr_size=16) {
  const LLAVE     = new TextEncoder().encode(LLAVECRYP).subarray(0,arr_size);
  const iv        = new Uint8Array(arr_size);
  const decipher  = new Cbc(Aes, LLAVE, iv, Padding.PKCS7);
  const encrypted = decipher.decrypt(base64.decode(texto));
  return new TextDecoder().decode( encrypted ) ;
}

function creaTotp(user:string) {
  const llave = base32.encode(new TextEncoder().encode( LLAVE+user ));
  let totp    = new OTPAuth.TOTP({
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
  .post("/encripta", (ctx) => {
   if (ctx.request.headers.has('aencriptar')) {
     ctx.response.body = encripta( ctx.request.headers.get('aencriptar') );
   } else {ctx.response.body = 'ERROR: Sin dato a encriptar';}
  })
  .post("/decripta", (ctx) => {
   if (ctx.request.headers.has('adecriptar')) {
     ctx.response.body = decripta( ctx.request.headers.get('adecriptar') );
   } else {ctx.response.body = 'ERROR: Sin dato a decriptar';}
  })
  .get("/tokenahora/:user", (context) => {
    if (context?.params?.user) {
        context.response.body = tokenNow(context.params.user);
    } else {ctx.response.body = 'ERROR: Falta parámetro';}
  })  
  .get("/tokenvalida/:user/:token", (context) => {
    if (context?.params?.token) {
      context.response.body = validaToken(context.params.user, context.params.token);
    } else {ctx.response.body = 'ERROR: Sin parámetros completos';}
  });

const app = new Application();
app.use(oakCors()); // Enable CORS for All Routes
app.use(router.routes());
app.use(router.allowedMethods());

await app.listen({ port: 8000 });
