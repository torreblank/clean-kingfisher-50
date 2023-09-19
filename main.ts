import { Application, Router } from "https://deno.land/x/oak@v12.6.1/mod.ts";
import { oakCors }      from "https://deno.land/x/cors@v1.2.2/mod.ts";
import * as OTPAuth     from "https://deno.land/x/otpauth@v9.1.4/dist/otpauth.esm.js"
import * as base32      from "https://deno.land/std/encoding/base32.ts";
import * as base64      from "https://deno.land/std/encoding/base64.ts";

const ISSUER    = Deno.env.get("ISSUER")
const LLAVE     = Deno.env.get("LLAVE")
const LLAVECRYP = Deno.env.get("LLAVECRYP")
const ALGORITMO = "AES-GCM";

async function encripta(data:string) {
    const iv = new Uint8Array(
               new TextEncoder().encode(LLAVECRYP).subarray(0,16));
    const key =new Uint8Array( 
               new TextEncoder().encode(LLAVECRYP).subarray(0,16));
    const key_encoded = await crypto.subtle.importKey(
      "raw", key.buffer, ALGORITMO, true, ["encrypt", "decrypt"],
    );
    const encrypted_data = await window.crypto.subtle.encrypt(
      {name:ALGORITMO, iv: iv,}, key_encoded, new TextEncoder().encode(data),
    );
    return base64.encode(encrypted_data);
}
async function decripta(data:any) {
    data = base64.decode(data);
    const iv = new Uint8Array(
               new TextEncoder().encode(LLAVECRYP).subarray(0,16));
    const key =new Uint8Array( 
               new TextEncoder().encode(LLAVECRYP).subarray(0,16));
    const key_encoded = await crypto.subtle.importKey(
        "raw", key.buffer, ALGORITMO, true, ["encrypt", "decrypt"],
    );
    const decrypted = await window.crypto.subtle.decrypt(
      {name:ALGORITMO, iv:iv,}, key_encoded, data,
    );
    return new TextDecoder().decode(decrypted);
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
  .get("/", (ctx:any) => {
    ctx.response.body = "[ API tutorial de JTK ]";
  })
  .post("/encripta", (ctx:any) => {
   if (ctx.request.headers.has('aencriptar')) {
       ctx.response.body = (async() => {return( await encripta(ctx.request.headers.get('aencriptar')) )});
   } else {ctx.response.body = 'Sin dato a encriptar';}
  })
  .post("/decripta", (ctx:any) => {
   if (ctx.request.headers.has('adecriptar')) {
       ctx.response.body = (async() => {return( await decripta(ctx.request.headers.get('adecriptar')) )});
   } else {ctx.response.body = 'Sin dato a decriptar';}
  })
  .get("/tokenahora/:user", (ctx:any) => {
    if (ctx?.params?.user) {
        ctx.response.body = tokenNow(ctx.params.user);
    } else {ctx.response.body = 'ERROR: Falta parámetro';}
  })  
  .get("/tokenvalida/:user/:token", (ctx:any) => {
    if (ctx?.params?.token) {
      ctx.response.body = validaToken(ctx.params.user, ctx.params.token);
    } else {ctx.response.body = 'ERROR: Sin parámetros completos';}
  });

const app = new Application();
app.use(oakCors()); // Enable CORS for All Routes
app.use(router.routes());
app.use(router.allowedMethods());

await app.listen({ port: 8000 });
