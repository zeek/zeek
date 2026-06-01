# ws-acldng.py

Code for LBL's netcontrol WebSocket acldng setup.


# Installation

```
$ python3 -m venv venv
$ . venv/bin/activate
$ pip install -r requirements.txt
```


# Test Run

```
ACLDNG_API_TOKEN=1234 python3 ws-acldng.py --nullroute-bulk-uri http://127.0.0.1:8080/nullroute-bulk
```
