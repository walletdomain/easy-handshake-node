package handshake.node.util;

/**
 * RE-ARCHITECTURE: single shared JSON string-escaping routine, used by
 * RpcServer, WebAdminServer, and DnsResource -- each of which
 * independently carried its own near-identical escape() implementation
 * before this existed. Direct comparison of the three found they'd
 * genuinely diverged, not just in style:
 *   - WebAdminServer's own jsonEscape() escaped only '"' and '\\',
 *     leaving '\n'/'\r' completely unescaped -- a real bug: any value
 *     containing a literal newline (not uncommon in free-text config
 *     values) would be emitted as invalid, line-broken JSON.
 *   - DnsResource's own jsonEscape() escaped '"', '\\', and '\n', but
 *     not '\r' -- the same class of bug, just one character narrower.
 *   - RpcServer's own jsonEscape() was the one complete version (all
 *     four characters), but RpcServer also carried a second, separate
 *     escape() used only for RPC error messages, which had the same
 *     gap as WebAdminServer's (just '"' and '\\') -- less often
 *     exercised since error messages rarely contain raw newlines, but
 *     the same latent bug if one ever did.
 * This is the complete, four-character version; every caller above now
 * delegates to it instead of keeping its own copy, so there is exactly
 * one place JSON string-escaping can drift or regress from here on.
 * <p>
 * RE-ARCHITECTURE: widened from package-private to public, along with
 * escape() itself, as part of the handshake.node.util split
 * (package-reorg-plan.md, Phase 3) -- RpcServer, WebAdminServer, and
 * DnsResource all stay outside this package and call escape() directly.
 */
public final class JsonUtil {
    private JsonUtil() {}

    public static String escape(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"'  -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                default   -> sb.append(c);
            }
        }
        return sb.toString();
    }
}