# Loopback Packet Deduplication Fix

## Problem
When using netdump to monitor the loopback interface (lo), each packet appeared twice in the output, causing a 2-packet exchange to show 4 packets. This happened because RAW sockets on loopback interfaces receive both the outgoing and incoming copies of each packet.

## Solution
Implemented automatic loopback interface detection and packet deduplication:

### Key Components
1. **Loopback Detection**: `is_loopback_interface()` function using `SIOCGIFFLAGS` ioctl
2. **Packet Hashing**: `packet_hash()` function creating unique identifiers based on:
   - Packet size
   - Source/destination ports  
   - Protocol type
   - Source/destination IP addresses
3. **Deduplication Cache**: 16-entry circular buffer with 2-second time window
4. **Selective Filtering**: Only applies deduplication on loopback interfaces

### Implementation Details
- Added global variable `is_loopback_iface` set during initialization
- Modified `print_packet()` to check cache before displaying packets
- Cache uses simple circular buffer to track recently seen packet hashes
- Time-based expiration prevents stale entries from blocking legitimate duplicates

### Backwards Compatibility
- Zero changes to behavior on non-loopback interfaces
- No performance impact on regular network monitoring
- All existing command-line options and features preserved

### Testing
- Unit tests verify hash function produces consistent results for identical packets
- Unit tests confirm loopback detection works correctly
- Code compiles without warnings and maintains C89 compliance

## Usage
No changes to command-line interface. The fix is automatically applied:
```bash
sudo ./netdump -i lo    # Deduplication active
sudo ./netdump -i eth0  # Normal behavior unchanged
```

The fix resolves issue #3 with minimal code changes while maintaining full compatibility.