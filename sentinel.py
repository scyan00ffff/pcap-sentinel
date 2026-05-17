from analysis import run 
import webbrowser
import threading 

if __name__ == "__main__": #only true when file ran directly not imported

    def open_browser():
        webbrowser.open('http://localhost:5000')

    #starts browser after one second delay in a new thread, allowing flask time to start 
    threading.Timer(1, open_browser).start()

    from report import start_server
    start_server()