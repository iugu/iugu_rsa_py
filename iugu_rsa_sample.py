# - Instalar "Crypto" usando o comando
# pip install pycryptodome
# - Instalar "Requests" usando o comando
# pip install requests
#  para executar:
#  - Altere a linha iuru_rsa.api_token, informando seu token
#  - Execute o arquivo com o comando abaixo:
# python ./iugu_rsa_sample.py
######################################################################################################
######################################################################################################
######################################################################################################

######################################################################################################
#                                           IUGU_RSA_SAMPLE
import json


class IUGU_RSA_SAMPLE:
    print_vars = False
    # Link de referência: https://dev.iugu.com/reference/autentica%C3%A7%C3%A3o#criando-chave-api-com-assinatura
    api_token = "TOKEN CREATED ON IUGU PANEL"
    # Link de referência: https://dev.iugu.com/reference/autentica%C3%A7%C3%A3o#segundo-passo
    file_private_key = "/file_path/private_key.pem"

    # Link de referência: https://dev.iugu.com/reference/autentica%C3%A7%C3%A3o#quinto-passo
    def __get_request_time(self):
        from datetime import datetime
        current_date = datetime.now().astimezone()
        return current_date.isoformat(timespec='seconds')

    def __get_private_key(self):
        from Crypto.PublicKey import RSA
        with open(self.file_private_key) as f:
            text_key = f.read()
        private_key = RSA.importKey(text_key)
        return private_key

    # Link de referência: https://dev.iugu.com/reference/autentica%C3%A7%C3%A3o#sexto-passo
    def __sign_body(self, method, endpoint, request_time, body, private_key):
        import base64
        from Crypto.Hash import SHA256
        from Crypto.Signature import PKCS1_v1_5
        ret_sign = ""
        pattern = method+"|"+endpoint+"\n"+self.api_token+"|"+request_time+"\n"+body
        h = SHA256.new(pattern.encode("utf8"))
        signer = PKCS1_v1_5.new(private_key)
        signature_bytes = signer.sign(h)
        ret_sign = base64.b64encode(signature_bytes).decode('utf-8')
        return ret_sign

    __last_response = ""

    def getLastResponse(self):
        return self.__last_response

    __last_response_code = 0

    def getLastResponseCode(self):
        return self.__last_response_code

    # Link de referência: https://dev.iugu.com/reference/autentica%C3%A7%C3%A3o#d%C3%A9cimo-primeiro-passo
    def __send_data(self, method, endpoint, data, response_code_ok):
        self.__last_response = ""
        self.__last_response_code = 0
        request_time = self.__get_request_time()
        body = data
        signature = self.__sign_body(
            method, endpoint, request_time, body, self.__get_private_key())

        if self.print_vars:
            print("endpoint: " + method + " - " + endpoint)
            print("request_time: " + request_time)
            print("api_token: " + self.api_token)
            print("body: " + body)
            print("signature: " + signature)

        import requests
        headers = {'Content-type': 'application/json',
                   'Accept': 'application/json',
                   'Request-Time': request_time,
                   'Signature': 'signature='+signature}
        if (method.upper() == 'POST'):
            r = requests.post('https://api.iugu.com'+endpoint,
                              data=body, headers=headers)
        else:
            raise Exception("method "+method+" not implemented")
        self.__last_response_code = r.status_code
        ret = self.__last_response_code == response_code_ok
        self.__last_response = r.text
        return ret

    # Link de referência: https://dev.iugu.com/reference/validate-signature
    def signature_validate(self, data):
        method = "POST"
        endpoint = "/v1/signature/validate"
        return self.__send_data(method, endpoint, data, 200)

    def transfer_requests(self, data):
        method = "POST"
        endpoint = "/v1/transfer_requests"
        return self.__send_data(method, endpoint, data, 202)
# ######################################################################################################


######################################################################################################
#                                    Example of use IUGU_RSA_SAMPLE
######################################################################################################
iuru_rsa = IUGU_RSA_SAMPLE()
iuru_rsa.api_token = ""
iuru_rsa.print_vars = True
iuru_rsa.file_private_key = "./private.pem"

# ######################################################################################################
# #                                         signature_validate
# # Link de referência: https://dev.iugu.com/reference/validate-signature
obj = {
    "api_token": iuru_rsa.api_token,
    "mensagem": "qualquer coisa"
}

if (iuru_rsa.signature_validate(json.dumps(obj))):
    print("Response: " + str(iuru_rsa.getLastResponseCode()) + iuru_rsa.getLastResponse())
else:
    print("Error: " + str(iuru_rsa.getLastResponseCode()) + iuru_rsa.getLastResponse())
######################################################################################################

######################################################################################################
#                                          transfer_requests
obj = {
    "api_token": iuru_rsa.api_token,
    "transfer_type": "pix",
    "amount_cents": 1,
    "receiver": {
        "pix": {
            "key": "00000000000",
            "type": "cpf"
        }
    }
}

if (iuru_rsa.transfer_requests(json.dumps(obj))):
    print("Response: " + str(iuru_rsa.getLastResponseCode()) + iuru_rsa.getLastResponse())
else:
    print("Error: " + str(iuru_rsa.getLastResponseCode()) + iuru_rsa.getLastResponse())
######################################################################################################
