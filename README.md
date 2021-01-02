# FastAPI Auth

FastAPI authentication boilerplate using OAuth 2 and JWT.

**Create secret key**  
The secret key is used to hash passwords. Start a Python shell and run the following to generate a new key:

```
import os
import binascii
binascii.hexlify(os.urandom(32))
```

The output will look similar to this:

```
9e8375ebde3579de068cd03e9bbbda73a703e81a210a3d539f79ce161d60f56a
```

Replace the secret_key in `.env` with the string generated.

**Serve API**

```
uvicorn main:app --reload
```

**API Docs**
View API endpoint documentation at `http://127.0.0.1:8000/docs`
