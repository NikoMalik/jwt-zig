private = openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:4096


public  = openssl pkey -in private_key.pem -pubout -out public_key.pem



