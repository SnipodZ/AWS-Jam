## No unencrypted databases allowed
**Pasos a realizar:**
1. Create a snapshot of the source DB instance
2. Encrypt the snapshot
3. Restore the encrypted DB snapshot

**1.**
Ir a snapshots, y darle a crear snapshot.
<img width="1225" height="485" alt="Pasted image 20250913161032" src="https://github.com/user-attachments/assets/7001b3c2-0765-4460-8a48-c8fd2341f769" />


**2.**
Hacemos copia de la snapshot, marcamos encriptación
<img width="810" height="258" alt="Pasted image 20250913161404" src="https://github.com/user-attachments/assets/8f76c806-0f3f-451a-b6ad-a6012e78f5da" />


**3.**

Restauramos snapshot. Hay que cambiar configuración del tipo de instancia, si no no dejará crear la copia.
<img width="784" height="306" alt="Pasted image 20250913163601" src="https://github.com/user-attachments/assets/aea72a73-5f2d-4b5f-b9ab-0d7c884c7c06" />

## Detective Homes has a Way!
### Task 1

```c
The CloudWatch log group named sensitive-data-01-lambda is currently logging Personal Identifiable Data (PID) information and has been configured with an incorrect data protection policy.

Your task is to determine the appropriate data protection policy that will obscure the PID information present in the CloudWatch log.
```

Hay que revisar logs para ver tipo de dato que se está guardando. Después en Data protection hay que seleccionar el tipo de dato correcto.
<img width="568" height="214" alt="Pasted image 20250913164147" src="https://github.com/user-attachments/assets/5dd2314d-1102-41ad-b3ea-b09e9e4d324d" />


### Task 2
Lo mismo de antes, pero hay más tipos de datos.
**Fecha de nacimiento y código postal**

<img width="603" height="234" alt="Pasted image 20250913164345" src="https://github.com/user-attachments/assets/c3b7b910-1853-4442-a81a-d0acba6e2a42" />


## Data with the Stars!

### Task 1
Hay que crear una S3 bucket policy. Según el ejercicio es el siguiente:
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Statement1",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::914365745100:user/USER-A"
            },
            "Action": "s3:Get*",
            "Resource": [
                "arn:aws:s3:::jam-challenge-patientdata-us-east-1-914365745100",
                "arn:aws:s3:::jam-challenge-patientdata-us-east-1-914365745100/*"
            ]
        },
        {
            "Sid": "Statement2",
            "Effect": "Deny",
            "Principal": {
                "AWS": "arn:aws:iam::914365745100:user/USER-B"
            },
            "Action": "s3:Get*",
            "Resource": [
                "arn:aws:s3:::jam-challenge-patientdata-us-east-1-914365745100",
                "arn:aws:s3:::jam-challenge-patientdata-us-east-1-914365745100/*"
            ]
        }
    ]
}
```

Se deniega acceso completo a **USER B**, mientras que permitimos el acceso de **USER A**

### Task 2

Nos piden subir fichero de prueba y habilitar el loggeo de accesos. Para eso hay un ajuste en concreto, es sencillo. En **propiedades**, bajar hasta **Server access logging**
<img width="939" height="852" alt="Pasted image 20250913171041" src="https://github.com/user-attachments/assets/48455f2d-7e0a-4d1e-83b3-ba550b035fa7" />
