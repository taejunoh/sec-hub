import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';

/** Test-only localhost server: exposes a PHP header, never executes PHP. */
export async function startHeaderFixture() {
  const server=createServer((request,response)=>{
    response.writeHead(200,{'Content-Type':'text/plain; charset=utf-8','X-Powered-By':'PHP/8.1.2','Server':'Sec-Hub-Test-Fixture'});
    response.end('Sec Hub local PHP header fixture. No PHP runtime or exploit code.\n');
  });
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  return {server,url:`http://127.0.0.1:${server.address().port}`,close:()=>new Promise(resolve=>server.close(resolve))};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  const fixture=await startHeaderFixture();console.log(fixture.url);
  process.once('SIGINT',()=>fixture.server.close());process.once('SIGTERM',()=>fixture.server.close());
}
