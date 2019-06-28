import time

'''
def log(*message):
    time_str = str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
    print('\n[%s] %s' % (time_str, *message), flush=True, end=' ')
'''


def log(*message,end='\n'):
    time_str = str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
    msg_str = ' '.join((str(i) for i in message))
    print('[%s] %s' % (time_str, msg_str), flush=True, end=end)