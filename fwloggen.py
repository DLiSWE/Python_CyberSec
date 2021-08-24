import datetime
from functools import partial
from ipaddress import ip_address
from itertools import cycle, product, islice
from random import randint, shuffle
import pytz
import time

fwlog = open("fakefwlog4.txt", "w")


'''
    This script creates logs matching the pattern 
    of the default firewall logs to act as a test script to
    simulate input coming from a firewall.

BASED OFF FIELDS:
Date|Time|Action|Protocall|src-ip|dst-ip|src-port|dst-port|size|
'''

# set to True to get ipv6 addresses in logs too
INCLUDE_IPV6 = False

#instantiate datetime
now = datetime.datetime.now(pytz.timezone('US/Eastern')).isoformat('T','seconds')
#randomize sleep buffer
timey = random.randint(1,10)

# random.choice acceleration stream
def random_choice_stream(collection, min_buffer=4096):
    ''' takes a collection of items and yields a
    random selection from it without needing to
    call for randomness on every selection. '''
    assert isinstance(collection, list), collection
    # multiply the collection to reduce shuffle ops
    while len(collection) < min_buffer:
        collection = collection * 2
    while shuffle(collection) is None:
        yield from collection

# cycler of connection ids
ids = cycle(range(1, 65536))


# random interface generation
interfaces = [f'eth{i}' for i in range(16)]
random_interfaces = random_choice_stream(interfaces)

# random ip generation
rand_ip_int = partial(
    randint, 
    1, 
    2**(128 if INCLUDE_IPV6 else 32)-1
)
def rand_ip():
    while True:
        try:
            return ip_address(rand_ip_int())
        except:
            continue

#random allow/deny
actions = ['ALLOW', 'DROP']
randomize_actions = random_choice_stream(actions)

# random protocol generation
protocols = ['UDP', 'TCP']
random_protocols = random_choice_stream(protocols)

# template for firewall log output
template = '{ts} {acti} PROTO={proto:} SRC={src:} DST={dst:} SPT={spt:} DPT={dpt:} LEN={length:} TTL={ttl:} ID={_id} ACK PSH URGP=0'.format


# glues everything together
def rand_template():
    return template(
        ts=now,
        acti=next(randomize_actions),
        proto=next(random_protocols),
        src=rand_ip(),
        dst=rand_ip(),
        spt=randint(1, 65536),
        dpt=randint(1, 65536),
        length=randint(1, 65536),
        ttl=randint(10, 4096),
        _id=next(ids)
    )

if __name__ == '__main__':
    while True:

        fwlog.write('\n'.join(
            rand_template() for i in range(timey)
        ))
