import { Application, Router } from "https://deno.land/x/oak@v12.6.1/mod.ts";
import { oakCors } from "https://deno.land/x/cors@v1.2.2/mod.ts";
import { base32Encode } from 'npm:@ctrl/ts-base32';
import { Buffer } from 'npm:buffer';
import * as OTPAuth from "https://deno.land/x/otpauth@v9.1.4/dist/otpauth.esm.js"

const issuer = Deno.env.get("ISSUER")

function validaToken(user:string, token_test:string) {
  //const issuer = '';
  var   llave  = issuer+user;
  llave = base32Encode(Buffer(llave));
  let totp = new OTPAuth.TOTP({
    issuer: issuer, label: user, algorithm: "SHA1",
    digits: 6, period: 30, secret: llave
  });
  return (totp.validate({token: token_test, window: 1 }) !== null)
}
function tokenNow(user:string) {
    //const issuer = '';
    var   llave  = issuer+user;
    llave = base32Encode(Buffer(llave));
    let totp = new OTPAuth.TOTP({
      issuer: issuer, label: user, algorithm: "SHA1",
      digits: 6, period: 30, secret: llave
    });
    // Generate a token as string
    return totp.generate();
}
const router = new Router();
router
  .get("/", (context) => {
    context.response.body = "Validar token TOTP: /usuario/token";
  })
  .get("/:user", (context) => {
    if (context?.params?.user) {
      context.response.body = "sólo 1 parámetro recibido:"+context.params.user+". Debe ser /user/token";
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
