#!/usr/bin/env python3

from bottle import route, run, post, request, error, abort

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random.random import randint


###
# crypto utilities
class Error(Exception):
    def __init__(self, status_code, msg):
        self.status = status_code
        self.msg = msg


PORT_NUMBER = 1234

ERROR_key_too_long = 490
ERROR_encipher = 491
ERROR_decipher = 492
ERROR_padding = 599

KEY = "that's not a key"


def pad_key(key):
    if len(key) in AES.key_size:
        return bytes(key, encoding="ASCII")
    size = 0
    for s in AES.key_size:
        if s > len(key) and (size == 0 or s < size):
            size = s
    if size == 0:
        raise Error(ERROR_key_too_long, "AES key is too long")
    print(bytes(key + '\0'*(size-len(key)), encoding="ASCII"))
    return bytes(key + '\0'*(size-len(key)), encoding="ASCII")


def encipher(cleartext, key):
    print(f"cleartext = '{cleartext}'")
    print(f"key = '{key}'")
    cleartext = cleartext
    padded_cleartext = pad(cleartext, AES.block_size)
    IV = bytes([randint(0, 255) for _ in range(AES.block_size)])
    try:
        cipher = AES.new(key, mode=AES.MODE_CBC, IV=IV)
        ciphertext = cipher.encrypt(padded_cleartext)
    except Exception as e:
        raise Error(ERROR_encipher, str(e))
    return IV+ciphertext


def decipher(ciphertext, key):
    print(AES.block_size)
    IV = ciphertext[0:AES.block_size]
    ciphertext = ciphertext[AES.block_size:]
    try:
        cipher = AES.new(key, mode=AES.MODE_CBC, IV=IV)
        padded_cleartext = cipher.decrypt(ciphertext)
    except Exception as e:
        raise Error(ERROR_decipher, str(e))
    try:
        cleartext = unpad(padded_cleartext, AES.block_size)
    except ValueError:
        raise Error(ERROR_padding, "padding error")
    return cleartext


###
# template
def template(html):
    return """
<style>
</style> """ + f"""
<h1>Attaque de Vaudenay (<i>"padding oracle attack"</i>)</h1>

{html}

<h3> liens </h3>
<p>
Ces liens ne sont pas nécessaires pour implémenter l'attaque mais vous
permettent de configurer le serveur en choisissant la clé et de tester le
chiffrement / déchiffrement. Vous pouvez aussi tester interactivement la
réponse du serveur sur un message chiffré erroné.
</p>
<p>
Vous devrez par contre <a href="./encipher">générer un message chiffré</a>
qui servira d'entrée à votre programme qui implémente l'attaque de Vaudenay.
</p>
<ul>
<li> <a href="./">index</a></li>
<li> <a href="./change_key">changer la clé</a></li>
<li> <a href="./encipher">chiffrer un message</a></li>
<li> <a href="./decipher">déchiffrer un message</a></li>
<li> <a href="./check">vérifier un message chiffré</a></li>
</ul>
"""


###
# routes

@route('/')
def index():
    return template("""
<h2>Description du serveur</h2>

<p>
Ceci est un petit serveur <a href="http://bottlepy.org">bottle</a> pour
expérimenter avec l'<a href="http://en.wikipedia.org/wiki/Padding_oracle_attack">attaque
de Vaudenay</a>. Le chiffrement / déchiffrement utilisent la bibliothèque <a
href="https://www.pycryptodome.org/en/latest/">PyCryptodome</a>.
</p>

<p>
Les seules requêtes nécessaires pour cette attaque sont des requête <tt>POST</tt> sur la
route <tt>/check_process</tt>, avec un champs <tt>ciphertext</tt>
contenant une chaine donnant le code hexadécimal du texte chiffré.
</p>

<p>
Pour faire ceci en Python, vous pourrez utiliser le code suivant, qui fait une
requête et renvoie le code de retour de cette requête : soit <tt>200</tt> (OK),
soit <tt>599</tt> (erreur de remplissage) :
<code>
<pre>
from urllib import request
from urllib.error import HTTPError, URLError

def check(ciphertext):
    "check ciphertext by sending a request to the server"
    url = f"http://localhost:{PORT_NUMBER}/check"
    data = bytes('ciphertext=' + ciphertext.hex(), encoding="ASCII")
    req = request.Request(url, data, method="POST")
    try:
        resp = request.urlopen(req)
        code = resp.getcode()
    except HTTPError as e:
        code = e.getcode()
    except URLError as e:
        import sys
        print(f"** connection problem: {e}.")
        print(f"** Is the server running on port {PORT_NUMBER}?")
        sys.exit(2)
    assert code in (200, 599)
    return code
</pre>
</code>
</p>

<p>
Vous pouvez transformer une chaine en héxadécimal (<tt>0123456789abcdef</tt>)
en tableau d'octets avec
<pre>
  B = bytearray.fromhex(chaine)
</pre>
</p>

<p>
Pour info, mon code (Python) pour l'attaque complète fait 125 lignes (en
comptant la fonction <tt>check</tt>) et a été écrit en 2h.
</p>
""")


@route('/change_key')
def change_key_form():
    return template(f"""
<h2> changement de clé </h2>

<form action="/change_key" method="post">
    clé (ASCII) : <input name="key" type="text" value="{KEY}" maxlength="32" size="32"/>
    <input value="Changer" type="submit" />
</form>

<p>
""")


@post('/change_key')
def change_key_process():
    global KEY
    KEY = request.forms.get('key').strip()
    pad_key(KEY)    # check sanity
    return change_key_form()


@route('/encipher')
def encipher_form():
    return template("""
<h2>Chiffrer un texte</h2>

<form action="/encipher" method="post">
    texte clair (ASCII) : <input name="clear" type="text" size="128" />
    <input value="Chiffrer" type="submit" />
</form>
""")


@post('/encipher')
def encipher_process():
    try:
        cleartext = bytes(request.forms.get('clear').strip(), encoding="ASCII")
        ciphertext = encipher(cleartext, pad_key(KEY))
        return template(f"""
<h2>Résultat du chiffrement</h2>

<p>text clair (ASCII): <tt>{cleartext.decode(encoding="ASCII")}</tt></p>
<p>clé (ASCII): <tt>{KEY}</tt></p>
<p>texte chiffré (héxadécimal) : <tt>{ciphertext.hex()}</tt></p>
""")
    except Error as e:
        abort(e.status, e.msg)


@route('/decipher')
def decipher_form():
    return template("""
<h2>Déchiffrer un texte</h2>

<form action="/decipher" method="post">
    texte chiffré (hexadécimal) : <input name="ciphertext" type="text" size="128"/>
    <input value="Déchiffrer" type="submit" />
</form>
""")


@post('/decipher')
def decipher_process():
    try:
        hex = request.forms.get('ciphertext').strip()
        ciphertext = bytes.fromhex(hex)
        cleartext = decipher(ciphertext, pad_key(KEY))
        return template(f"""
<h2>Résultat du déchiffrement</h2>

<p>text clair (ASCII): <tt>{cleartext.decode(encoding="ASCII")}</tt></p>
""")
    except Error as e:
        abort(e.status, e.msg)


@route('/check')
def check_form():
    return template("""
<h2>Envoyer un texte chiffré pour vérification</h2>

<form action="/check" method="post">
    texte chiffré (hexadécimal) : <input name="ciphertext" type="text" size="128"/>
    <input value="Vérifier" type="submit" />
</form>
    """)


@post("/check")
def check_process():
    try:
        hex = request.forms.get('ciphertext').strip()
        ciphertext = bytes.fromhex(hex)
        decipher(ciphertext, pad_key(KEY))
        return template(f"""
<h2>Vérification d'un texte chiffré</h2>

<p> texte chiffré <tt>{hex.upper()}</tt> <b>OK</b></p>
""")
    except Error as e:
        abort(e.status, e.msg)


@error(ERROR_key_too_long)
@error(ERROR_encipher)
@error(ERROR_decipher)
@error(ERROR_padding)
def error_page(error):
    return template(f"""
<h2>ERREUR {error.status_code}</h2>

<p>message : <tt>{error.body}</tt></p>
""")


if __name__ == "__main__":
    from sys import argv
    if len(argv) > 2:
        print(f"usage: {argv[0] [KEY]}")
        exit(1)

    if len(argv) > 1:
        KEY = argv[1]
        pad_key(KEY)
    else:
        # import string
        # alpha = string.ascii_letters + string.digits
        # KEY = "".join([alpha[randint(0, len(alpha)-1)] for _ in range(16)])
        KEY = "that's not a key"

    # run(host='localhost', port=PORT_NUMBER, debug=True, reloader=True)
    # run(host='localhost', port=PORT_NUMBER, debug=True)
    run(host='localhost', port=PORT_NUMBER)
