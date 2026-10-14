package handshake.node.util;

/**
 * The node's notion of "now" for block building and submitted-block time checks, with hsd's
 * {@code setmocktime} behaviour: the RPC shifts this clock by a fixed offset so that
 * {@code nowSec()} reads the given timestamp at the moment of the call and then keeps running.
 * Only time used for mining/block-time rules goes through here; peer handshakes and log times
 * stay on the real clock.
 */
public final class NodeClock {
    private NodeClock() {}

    private static volatile long offsetSec = 0;

    public static long nowSec() { return System.currentTimeMillis() / 1000 + offsetSec; }

    /** hsd setmocktime: offset = timestamp - real now. */
    public static void setMockTime(long timestamp) { offsetSec = timestamp - System.currentTimeMillis() / 1000; }

    public static long offsetSec() { return offsetSec; }
}