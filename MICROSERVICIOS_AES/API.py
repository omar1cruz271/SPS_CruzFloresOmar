from flask import Flask, render_template, request, redirect, url_for
import datetime
from flask import Flask, url_for, jsonify, request
from flask.ext.sqlalchemy import SQLAlchemy
import random
from Crypto.Cipher import AES
from Crypto import Random
import os
import io
import PIL.Image as Image
#Import image processing standard library
from PIL import Image
#Import the pycrypto library, reference the aes encryption module, need to be installed through the pip command under cmd (installation is more troublesome)
from Crypto.Cipher import AES
import random
import string



app = Flask(__name__)
 
#Randomly generate 16 strings composed of lowercase letters
def key_generator(size = 16, chars = string.ascii_lowercase):
    return ''.join(random.choice(chars) for _ in range(size))



filename = "/home/omar/Escritorio/SPS/API_AES/static/salida"
filename_encrypted_ecb = "/home/omar/Escritorio/SPS/API_AES/"+"image_eECB"
filename_encrypted_cbc= "/home/omar/Escritorio/SPS/API_AES/"+"imagen_eCBC"
filename_encrypted_ofb = "/home/omar/Escritorio/SPS/API_AES/"+"image_eOFB"
filename_encrypted_cfb= "/home/omar/Escritorio/SPS/API_AES/"+"imagen_eCFB"
base_url= "/api/sps/helloworld/v1"
IV= key_generator(16)
format = "BMP"
#Using a function to randomly generate a string of lowercase letters
key = key_generator(16)


# AES encrypted plaintext space is an integer multiple of 16, which cannot be divided evenly, so it needs to be filled
#In the corresponding ascii, "\x00" means 0x00, the specific value is NULL, b means that it is expressed in bytes
def pad(data):
    return data + b"\x00" * (16 - len(data) % 16)


# Map the image data to RGB
def trans_format_RGB(data):
    #tuple: Immutable, ensure that data is not lost
    red, green, blue = tuple(map(lambda e: [data[i] for i in range(0, len(data)) if i % 3 == e], [0, 1, 2]))
    pixels = tuple(zip(red, green, blue))
    return pixels

#############################################  INICIO ECB ##########################################################
def encrypt_image_ecb(im):
    #Open the bmp picture and convert it to RGB image
    #im = Image.open(filename)
    #Convert image data into pixel value bytes
    value_vector = im.convert("RGB").tobytes()

    imlength = len(value_vector)
    #for i in range(original):
        #print(data[i])
    #Map the pixel value of the filled and encrypted data
    value_encrypt = trans_format_RGB(aes_ecb_encrypt(key, pad(value_vector))[:imlength])
    #for i in range(original):
        #print(new[i])

    #Create a new object, store the corresponding value
    im2 = Image.new(im.mode, im.size)
    im2.putdata(value_encrypt)

    # Save the object as an image in the corresponding format
    im2.save(filename_encrypted_ecb + "." + format, format)
    ruta= "/home/omar/Escritorio/SPS/API_AES/static/salida"
    rannum=str(random.randint(0,99))
    ruta+=rannum+"."+format
    im2.save(ruta)
    return rannum


def AES_ecb_decrypt(img):

    #img=Image.open(filename_encrypted_ecb+"."+format) 
    value_vector = img.convert("RGB").tobytes()
    
    imlength = len(value_vector)
    value_encrypt=img.getdata()

    ecb_decipher = AES.new(key, AES.MODE_ECB)
    plain_data = ecb_decipher.decrypt(value_vector)

    im2 = Image.new(img.mode, img.size)#referencia a la clase Image(PIL)
    im2.putdata(trans_format_RGB(plain_data))
    #bytes = readimage(path+extension)
    im2.save("image_eECB_dECB.jpg")
    ruta= "/home/omar/Escritorio/SPS/API_AES/static/salida"
    rannum=str(random.randint(0,99))
    ruta+=rannum+"."+format
    im2.save(ruta)
    return rannum

# ECB encryption
def aes_ecb_encrypt(key, data, mode=AES.MODE_ECB):
    #The default mode is ECB encryption
    aes = AES.new(key, mode)
    new_data = aes.encrypt(data)
    return new_data
############################################################################fin ECB #################################################


########################################################################## CBC#############################################
def encrypt_image_cbc(im):
    #Open the bmp picture and convert it to RGB image
    #im = Image.open(filename)
    value_vector = im.convert("RGB").tobytes()

    # Convert image data to pixel value bytes
    imlength = len(value_vector)

    # Perform pixel value mapping on the filled and encrypted data
    value_encrypt = trans_format_RGB(aes_cbc_encrypt(key, pad(value_vector))[:imlength])

    # Create a new object, store the corresponding value
    im2 = Image.new(im.mode, im.size)
    im2.putdata(value_encrypt)

    # Save the object as an image in the corresponding format
    im2.save(filename_encrypted_cbc + "." + format, format)
    ruta= "/home/omar/Escritorio/SPS/API_AES/static/salida"
    rannum=str(random.randint(0,99))
    ruta+=rannum+"."+format
    im2.save(ruta)
    return rannum
    #AES_cbc_decrypt(key,IV)
    #AES_ecb_decrypt(key)
def AES_cbc_decrypt(img):

    #img=Image.open(filename_encrypted_cbc+"."+format) 
    value_vector = img.convert("RGB").tobytes()

    imlength = len(value_vector)
    value_encrypt=img.getdata()

    cfb_decipher = AES.new(key, AES.MODE_CBC, IV)
    plain_data = cfb_decipher.decrypt(value_vector)
    im2 = Image.new(img.mode, img.size)#referencia a la clase Image(PIL)
    im2.putdata(trans_format_RGB(plain_data))
    #bytes = readimage(path+extension)
    im2.save("image_eCBC_dCBC.jpg")
    ruta= "/home/omar/Escritorio/SPS/API_AES/static/salida"
    rannum=str(random.randint(0,99))
    ruta+=rannum+"."+format
    im2.save(ruta)
    return rannum

    
 

# CBC encryption
def aes_cbc_encrypt(key, data, mode=AES.MODE_CBC):
    #IV is a random value
    #global IV
    #IV = key_generator(16)
    print("          ",IV)
    aes = AES.new(key, mode, IV)
    new_data = aes.encrypt(data)

    return new_data
##################################################################### FIN CBC ##########################################################

########################################################################## OFB#############################################
def encrypt_image_ofb(im):
    #Open the bmp picture and convert it to RGB image
    #im = Image.open(filename)
    value_vector = im.convert("RGB").tobytes()

    # Convert image data to pixel value bytes
    imlength = len(value_vector)

    # Perform pixel value mapping on the filled and encrypted data
    value_encrypt = trans_format_RGB(aes_ofb_encrypt(key, pad(value_vector))[:imlength])

    # Create a new object, store the corresponding value
    im2 = Image.new(im.mode, im.size)
    im2.putdata(value_encrypt)

    # Save the object as an image in the corresponding format
    im2.save(filename_encrypted_ofb + "." + format, format)
    ruta= "/home/omar/Escritorio/SPS/API_AES/static/salida"
    rannum=str(random.randint(0,99))
    ruta+=rannum+"."+format
    im2.save(ruta)
    return rannum

def AES_ofb_decrypt(img):

    #img=Image.open(filename_encrypted_ofb+"."+format) 
    value_vector = img.convert("RGB").tobytes()

    imlength = len(value_vector)
    value_encrypt=img.getdata()

    cfb_decipher = AES.new(key, AES.MODE_OFB, IV)
    plain_data = cfb_decipher.decrypt(value_vector)
    im2 = Image.new(img.mode, img.size)#referencia a la clase Image(PIL)
    im2.putdata(trans_format_RGB(plain_data))
    #bytes = readimage(path+extension)
    im2.save("image_eOFB_dOFB.jpg")
    ruta= "/home/omar/Escritorio/SPS/API_AES/static/salida"
    rannum=str(random.randint(0,99))
    ruta+=rannum+"."+format
    im2.save(ruta)
    return rannum

# OFB encryption
def aes_ofb_encrypt(key, data, mode=AES.MODE_OFB):
    #IV is a random value
    #global IV
    #IV = key_generator(16)
    print("          ",IV)
    aes = AES.new(key, mode, IV)
    new_data = aes.encrypt(data)

    return new_data
##################################################################### FIN OFB ##########################################################







############################################################## RUTAS ##########################################################
@app.route(base_url+'/AES/<action>/<mode>', methods=["POST"])
def cifrar_descifrar(mode, action):
    img=request.files["image"]
    print(img.name)
    img=Image.open(img)
    global key
    key=request.form.get("key")
    global IV
    IV=request.form.get("IV")
    if len(IV)!=16 or len(key)!=16:  #compruebo que la llave y/o el vector sean de 16 bits
        return "Ocurrió un error con la longitud de llave o vector",403
    if action=="cifrar":
        if mode=="CBC":
            num=encrypt_image_cbc(img)
        elif mode=="ECB":
            num=encrypt_image_ecb(img)
        elif mode=="OFB":
            num=encrypt_image_ofb(img)
        else:
            return "NO se reconoce el modo de operación AES que deseas ejecutar", 406
    elif action=="descifrar":
        if mode=="CBC":
            num=AES_cbc_decrypt(img)
        elif mode=="ECB":
            num=AES_ecb_decrypt(img)
        elif mode=="OFB":
            num=AES_ofb_decrypt(img)
        else:
            return "NO se reconoce el modo de operación AES que deseas ejecutar", 406
    else:
        return "NO se reconoce la acción que deseas ejecutar, asegurate que sea cifrar o descifrar", 405

    nombre="salida"+num+"."+format
    return jsonify({"action": action, "ruta": nombre}),201

@app.route(base_url+'/AES/<action>/<mode>')
def modo(mode,action):
    print(mode,action)
    return jsonify({'modo': mode, 'action': action}), 201

@app.route(base_url+'/AES/<action>')
def inicio(action):
    
    if action!= "cifrar" and action !="descifrar":
        return "bad request", 403
    return jsonify({"action":action, "modos": ["CBC", "ECB", "OFB" ]}),201

@app.route(base_url+"/AES")
def hello_networkers():
    return jsonify({"action": ["cifrar", "descifrar"]}),201

if __name__ == '__main__':
    app.run(debug=True)

