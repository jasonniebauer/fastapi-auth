# FastAPI Auth

Boilerplate authentication for FastAPI.

**Serve API**

```
uvicorn main:app --reload
```

**Create secret key**  
Start a Python shell and run the following:

```
import os
import binascii
binascii.hexlify(os.urandom(32))
```

The output will look similar to this:

```
9e8375ebde3579de068cd03e9bbbda73a703e81a210a3d539f79ce161d60f56a
```
