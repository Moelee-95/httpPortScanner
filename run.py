import logging
import threading
import time

try:
    import urllib.request as urllib2
except ImportError:
    import urllib2


def check(port,hosturl):
    try:
        #open a connection to a URL using urllib2
        webUrl = urllib2.urlopen(str(hosturl)+":"+port)
        #get the result code and print it
        print(port)
        return str(webUrl.getcode())
    except:
        pass
    


def main(hosturl):
    port = '75'
    count = 0
    while count <= 65536:
        try:
            output = threading.Thread(target=check, args=(port,hosturl))
            output.start()
            #output.join()
            print("result code: " + output)

        except:
            #print(port, " NO")
            port = int(port)+1
            port = str(port)
            count = count+1
            
            # read the data from the URL and print it
            #data = webUrl.read()
            #print(data)
            
if __name__ == "__main__":
  main("http://127.0.0.1")
  
