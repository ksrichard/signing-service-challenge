Signature Service Coding Challenge
---

This project is a simple API which exposes endpoints to create new Signature Devices and sign any textual messages with those.

How it works
---
This project exposes a REST API to create signature devices, sign messages, list signature devices and get specific signature device info.

All the new signature devices are having a newly generated public/private keypair and it keeps track the number of signatures made with that device.
All the devices are stored in memory for now, but since there is a simple interface, it can be easily modified or implemented using a database.

### Endpoints
- `POST /api/v0/signature-device` - Create a new signature device
- `GET /api/v0/signature-device` - List all signature devices
- `GET /api/v0/signature-device/{id}` - Get specific signature device info
- `GET /api/v0/sign-tx` - Signing a message with a signature device

### Examples

**Create new Signature Device**

Request:
```shell
curl --location 'http://127.0.0.1:8080/api/v0/signature-device' \
--header 'Content-Type: application/json' \
--data '{
    "algorithm": "RSA",
    "label": "label 1"
}'
```

Response:
```json
{
    "data": {
        "id": "2f4dd8f281c742dc96ff382f71614976"
    }
}
```

---

**List all Signature Devices**

Request:
```shell
curl --location 'http://127.0.0.1:8080/api/v0/signature-device'
```

Response:
```json
{
  "data": [
    {
      "id": "2f4dd8f281c742dc96ff382f71614976",
      "algorithm": "RSA",
      "publicKey": "LS0tLS1CRUdJTiBSU0FfUFVCTElDX0tFWS0tLS0tCk1FZ0NRUUQyalV1dkdSNk9zZ2poV3J3SFdYV3d4MUxEMXVock93aldLSjI1SHM5aVExaWJZa2liVUFJNFdacU0KTkRYamRTNEY0WUI1eW8xa3l0eFRNbWJneFh2ckFnTUJBQUU9Ci0tLS0tRU5EIFJTQV9QVUJMSUNfS0VZLS0tLS0K",
      "label": "label 1",
      "signatureCounter": 0
    }
  ]
}
```

---

**Get specific Signature Device**

Request:
```shell
curl --location 'http://127.0.0.1:8080/api/v0/signature-device/2f4dd8f281c742dc96ff382f71614976'
```

Response:
```json
{
  "data": {
    "id": "2f4dd8f281c742dc96ff382f71614976",
    "algorithm": "RSA",
    "publicKey": "LS0tLS1CRUdJTiBSU0FfUFVCTElDX0tFWS0tLS0tCk1FZ0NRUUQyalV1dkdSNk9zZ2poV3J3SFdYV3d4MUxEMXVock93aldLSjI1SHM5aVExaWJZa2liVUFJNFdacU0KTkRYamRTNEY0WUI1eW8xa3l0eFRNbWJneFh2ckFnTUJBQUU9Ci0tLS0tRU5EIFJTQV9QVUJMSUNfS0VZLS0tLS0K",
    "label": "label 1",
    "signatureCounter": 0
  }
}
```

---

**Signing data with a Signature Device**

Request:
```shell
curl --location 'http://127.0.0.1:8080/api/v0/sign-tx' \
--header 'Content-Type: application/json' \
--data '{
    "deviceId": "2f4dd8f281c742dc96ff382f71614976",
    "data": "some data"
}'
```

Response:
```json
{
  "data": {
    "signature": "xpzeYh036lN+yC7jcctUdG/5xftSueTFczhXrqqN4xLlky1qvF1k1jfz8f5KzRetdE1XCUL3Y7GxGKU5cX0dtg==",
    "signed_data": "1_some data_Zf2o6IV4Ki27krs0kg7XdmnM2p85fTCi3n6AQPret2ru9fWYu9SQ46/zuNAIUQ800me1vDP1eN4eAydEZMKq6A=="
  }
}
```


Usage
---

### Build
```shell
go build -o service
```

### Run
```shell
./service
```