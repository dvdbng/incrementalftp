#!/usr/bin/env python
#-*- coding: utf-8 -*-

from ftplib import FTP
import os
import pickle

def load_hosts():
    home = os.environ['HOME']
    file = home + "/.ftphosts"
    if os.path.exists(file):
        r = pickle.load(open(file,"rb"))
        if r and (type(r) == type([])):
            return r
        else:
            return []
    else:
        return []

def load_ftpinfo():
    print("=========================> load ftp info")
    if os.path.exists("./.ftp"):
        r = pickle.load(open("./.ftp","rb"))
        if r and (type(r) == type({})):
            return r
        else:
            return config_ftp()
    else:
        return config_ftp()

def save_hosts(hosts):
    home = os.environ['HOME']
    file = home + "/.ftphosts"
    f = open(file,"wb")
    pickle.dump(hosts,f,-1)
    f.close()

def save_ftpinfo(ftpinfo):
    print("=========================> Guardando ftp info")
    file = './.ftp'
    f = open(file,"wb")
    pickle.dump(ftpinfo,f,-1)
    f.close()

def config_ftp():
    host = select_ftp()
    pr = raw_input("Introduce el path remoto:")
    host['path'] = pr
    save_ftpinfo(host)
    return host


def select_ftp():
    hosts = load_hosts()
    i=0
    for k in hosts:
        print "(%s): %s" % (i,k['name'])
    print "(N): Nuevo"

    valido = False
    while not valido:
        r = raw_input(">").lower()
        if r == "n":
            break
        try:
            n = int(r)
            if n>=0 and n<len(hosts):
                break
        except Exception,ex:
            pass
        print("Valor invalido. Por favor, introduce un valor valido")

    if r=='n':
        return nuevo_host()
    else:
        return hosts[int(r)]

def nuevo_host():
    print("==>NUEVO HOST")
    name = raw_input("Nombre:")
    host = raw_input("Host:")
    port = raw_input("Port (21):")
    try:
        port = int(port)
    except Exception, ex:
        port = 21
    user = raw_input("User:")
    pas  = raw_input("Password:")
    nh = {
        'name': name,
        'host':host,
        'port':port,
        'user':user,
        'pw':pas
    }
    h = load_hosts()
    h.append(nh)
    save_hosts(h)
    return nh

def get_ftp(h):
    try:
        f = FTP()
        f.connect(h['host'],h['port'])
        f.login(h['user'],h['pw'])
        return f
    except Exception,ex:
        print ("Error conectando FTP")
        print(ex)

def menu(host):
    print("Selecciona opción:")
    print("(1) (V)er archivos que han cambiado")
    print("(2) (S)incronizar")
    print("(3) Ver (I)nformación de el host")
    print("(4) (C)omprobar con servidor remoto")
    print("(5) I(G)norar")
    print("(6) (M)arcar como modificado")
    print("(7) S(A)lir")
    op = raw_input(">").lower()
    if op == '1' or op == 'v':
        fu = FtpUpload()
        fu.setMd5Data(host.get('hashs',{}))
        fu.list()
    elif op == '2' or op == 's':
        info = load_ftpinfo()
        fu = FtpUpload()
        fu.setHost(info['host'],info['user'],info['pw'])
        fu.setMd5Data(info.get('hashs',{}))
        fu.upload(info.get("path",'.'),'.')
        fu.deleteOldFiles()
        fu.finish()
    elif op == '3' or op == 'i':
        print(host)
    elif op == '4' or op == 'c':
        phpcheck(host)
    elif op == '5' or op == 'g':
        ignore()
    elif op == '6' or op == 'm':
        mark()
    elif op == '7' or op == 'a':
        return
    else:
        print("Selecciona una opción valida")
    menu(host)


import urllib

def md5file(fi):
    m = hashlib.md5()
    f = open(fi, "rb")
    for l in f.readlines():
        m.update(l)
    return m.digest()

def ignore():
    f = raw_input("Introduce nombre de el archivo a ignorar: ")
    h = load_ftpinfo()

    if os.path.exists(f):
        h['hashs'][f] = md5file(f)
        print("Marcado %s como no modificado/no nuevo" % f)
    else:
        if h['hashs'].has_key(f):
            del h[hash][f]
            print("Marcado %s como no borrado" % f)
    save_ftpinfo(h)

def mark():
    f = raw_input("Introduce nombre de el archivo a marcar como modificado: ")
    h = load_ftpinfo()

    if os.path.exists(f):
        h['hashs'][f] = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
        print("Marcado %s como no modificado" % f)
        save_ftpinfo(h)



def php_check_files(url,checkfiles,checkhashes):
    info = load_ftpinfo()
    h = info.get('hashs',{})

    datos = "as=sd"
    n = 1
    for i in checkfiles:
        datos += ("&f%s=%s" % (n,i))
        n+=1
    f = urllib.urlopen(url,datos).read().strip("\n\r\t ").split('\n')

    if len(f) < len(checkhashes):
        for i in range(len(checkhashes)-len(f)):
            f.append("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")

    for i in range(0,len(checkhashes)):
        if checkhashes[i] != f[i]:
            h[checkfiles[i]] = f[i]
            print("FILE CHANGED: %s (%s => %s) " % (checkfiles[i],checkhashes[i],f[i]))

    info['hashs'] = h
    save_ftpinfo(info)

def phpcheck(host,src="."):
    url = raw_input("escribe la direccion remota: ")
    srcpath = path.path(src)
    checkfiles = []
    checkhashes = []
    for thispath in srcpath.walkfiles():
        thatpath = srcpath.relpathto(thispath)
        thatpathstr = str(thatpath)
        m = hashlib.md5()
        f = open(thispath, "rb")
        for l in f.readlines():
            m.update(l)
        thisMd5 = m.hexdigest()

        checkfiles.append(thatpath)
        checkhashes.append(thisMd5)

        if(len(checkfiles) >= 50):
            php_check_files(url,checkfiles,checkhashes)
            checkfiles = []
            checkhashes = []
    php_check_files(url,checkfiles,checkhashes)


import ftplib, pickle, sys, hashlib, os, string
import path         # http://www.jorendorff.com/articles/python/path

class loggger():
    def info(self,str,*a):
        print("[ext] " + str)

logging = loggger()

class Tracer:
    def __init__(self, name, fout):
        self.myname = name
        self.fout = fout

    def __getattr__(self, name):
        return lambda *a, **k: self.fout.write("%s.%s(%s, %s)\n" % (self.myname, name, a, k))

class EzFtp:
    """
    A simplified interface to ftplib.

    Lets you use full pathnames, with server-side
    directory management handled automatically.
    """
    def __init__(self, ftp):
        self.ftp = ftp
        self.serverDir = ''

    def setRoot(self, dir):
        """
        Set the remote directory that we'll call the root.
        """
        self.ftp.cwd(dir)

    def cd(self, dir, create=1):
        """
        Change the directory on the server, if need be.
        If create is true, directories are created if necessary to get to the full path.
        Returns true if the directory is changed.
        """
        if dir != self.serverDir:
            # Move up to the common root.
            while not dir.startswith(self.serverDir):
                logging.info("ftpcd ..")
                self.ftp.cwd("..")
                self.serverDir = os.path.split(self.serverDir)[0]
            # Move down to the right directory
            doDirs = dir[len(self.serverDir):]
            for d in string.split(doDirs, os.sep):
                if d:
                    try:
                        logging.info("ftpcd %s" % d)
                        self.ftp.cwd(d)
                    except:
                        if create:
                            logging.info("ftpmkdir %s" % d)
                            self.ftp.mkd(d)
                            self.ftp.cwd(d)
                        else:
                            return 0
                    self.serverDir = os.path.join(self.serverDir, d)
        return 1

    def putasc(self, this, that):
        """
        Put a text file to the server.
        """
        thatDir, thatFile = os.path.split(that)
        self.cd(thatDir)
        f = open(this, "r")
        logging.info("ftpstorasc %s" % that)
        self.ftp.storlines("STOR "+thatFile, f)

    def putbin(self, this, that):
        """
        Put a binary file to the server.
        """
        thatDir, thatFile = os.path.split(that)
        self.cd(thatDir)
        f = open(this, "rb")
        logging.info("ftpstorbin %s" % that)
        self.ftp.storbinary("STOR "+thatFile, f)

    def delete(self, that):
        """
        Delete a file on the server.
        """
        thatDir, thatFile = os.path.split(that)
        if self.cd(thatDir, 0):
            logging.info("ftpdel %s" % that)
            try:
                self.ftp.delete(thatFile)
            except:
                pass

    def quit(self):
        """
        Quit.
        """
        self.ftp.quit()


class FtpUpload():
    """
    Provides intelligent FTP uploading of files, using MD5 hashes to track
    which files have to be uploaded.  Each upload is recorded in a local
    file so that the next upload can skip the file if its contents haven't
    changed.  File timestamps are ignored, allowing regenerated files to
    be properly uploaded only if their contents have changed.

    Call `setHost` and `setMd5File` to establish the settings for a session,
    then `upload` for each set of files to upload.  If you want to have
    removed local files automatically delete the remote files, call
    `deleteOldFiles` once, then `finish` to perform the closing bookkeeping.

    ::

        fu = FtpUpload()
        fu.setHost('ftp.myhost.com', 'myusername', 'password')
        fu.setMd5File('myhost.md5')
        fu.upload(
            hostdir='www', src='.',
            text='*.html *.css', binary='*.gif *.jpg'
        )
        # more upload() calls can go here..
        fu.deleteOldFiles()
        fu.finish()

    """

    def __init__(self):
        self.ftp = None
        self.ezftp = None
        self.md5file = None
        self.md5DictIn = {}
        self.md5DictOut = {}
        self.md5DictUp = {}

    def setHost(self, host, username, password):
        """
        Set the host, the username and password.
        """
        assert not self.ftp
        self.ftp = ftplib.FTP(host, username, password)
        self.ftp.set_pasv(1)
        self.ftp.set_debuglevel(1)

    def setMd5Data(self, md5data):
        self.md5DictIn = md5data
        self.md5DictUp.update(self.md5DictIn)

    def upload(self,
               hostdir='.',
               src='.'
               ):
        """
        Upload a set of files.
        Source files are found in the directory named by `src`
        (and its subdirectories recursively).  The files are uploaded
        to the directory named by `hostdir` on the remote host.

        This method can be called a number of times to upload different
        sets of files to or from different directories within the same
        FtpUpload session.
        """

        if not self.ezftp:
            if not self.ftp:
                self.ftp = Tracer('ftp', sys.stdout)
            self.ezftp = EzFtp(self.ftp)

        if hostdir != '.':
            self.ezftp.setRoot(hostdir)

        print("Subiendo archivos...")

        # Walk the tree, putting files to the ezftp.
        srcpath = path.path(src)

        n = 0L

        for thispath in srcpath.walkfiles():

            if n > 1024*100:  #100Kb
                print("=========>Guardando hashes")
                self.save_hashs()
                n = 0

            thatpath = srcpath.relpathto(thispath)
            thatpathstr = str(thatpath)
            # Compute this file's MD5 fingerprint
            m = hashlib.md5()
            f = open(thispath, "rb")
            for l in f.readlines():
                m.update(l)
            thisMd5 = m.digest()

            # What was the last MD5 fingerprint?
            thatMd5 = self.md5DictIn.get(thatpathstr, '')

            # If the current file is different, then put it to the server.
            if thisMd5 != thatMd5:
                print("Subiendo %s" % thispath)
                # Find the pattern the file matches, and use the ftp function
                # from the map.
                #f = os.popen('file --mime-encoding -b "%s"' % thispath, 'r')
                try:
                    n += os.path.getsize(thispath)
                    if False:  #and f.read().startswith('us-ascii'):
                        self.ezftp.putasc(thispath, thatpath)
                    else:
                        self.ezftp.putbin(thispath, thatpath)

                    self.md5DictOut[thatpathstr] = thisMd5
                    self.md5DictUp[thatpathstr] = thisMd5
                except Exception,ex:
                    print("ERROR: %s" %ex )
                    self.md5DictOut[thatpathstr] = "error"
                    self.md5DictUp[thatpathstr] = "error"

            else:
                self.md5DictOut[thatpathstr] = thisMd5
                self.md5DictUp[thatpathstr] = thisMd5

    def list(self,src='.'):
        info = load_ftpinfo()
        hash = info['hashs']
        # Walk the tree, putting files to the ezftp.
        print("+---+--------------------------------------")
        srcpath = path.path(src)
        cambiado = 0
        nuevos = 0
        nocambiado = 0
        borrado = 0
        for thispath in srcpath.walkfiles():
            thatpath = srcpath.relpathto(thispath)
            thatpathstr = str(thatpath)
            # Compute this file's MD5 fingerprint


            # What was the last MD5 fingerprint?
            thatMd5 = hash.get(thatpathstr, '')

            # If the current file is different, then put it to the server.
            if thatMd5 == '':
                print("| N | " + thatpathstr)
                nuevos += 1
            else:
                m = hashlib.md5()
                f = open(thispath, "rb")
                for l in f.readlines():
                    m.update(l)
                thisMd5 = m.digest()
                if thisMd5 != thatMd5:
                    print("| C | " + thatpathstr)
                    cambiado += 1
                else:
                    nocambiado += 1

        for k in hash:
            if not os.path.exists(k):
                borrado += 1
                print("| D | " + k)

        print("+---+--------------------------------------")
        print("%s Archivos nuevos, %s han cambiado y %s no no han cambiado. %s han sido borrados" % (nuevos,cambiado,nocambiado,borrado))
        print("%s Archivos en total" % (nuevos+cambiado+nocambiado))
    def deleteOldFiles(self):
        """
        Delete any remote files that we have uploaded previously but
        that weren't considered in this FtpUpload session.  This doesn't
        touch files that exist on the remote host but were never uploaded
        by this module.
        """

        # Files in md5DictIn but not in md5DictOut must have been removed.
        for this in self.md5DictIn:
            if this not in self.md5DictOut:
                self.ezftp.delete(this)
                del self.md5DictUp[this]
        self.save_hashs()
    def save_hashs(self):
        info = load_ftpinfo()
        info['hashs'] = self.md5DictUp
        save_ftpinfo(info)

    def finish(self):
        """
        Do our final bookkeeping.
        """
        self.ezftp.quit()

        self.save_hashs()


try:
    menu(load_ftpinfo())
except (KeyboardInterrupt, SystemExit):
    print ("\nBye")
