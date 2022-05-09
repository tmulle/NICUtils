package me.mulle.utilities.network;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class that contains some useful methods for working with Network
 * Interfaces and InetAddresses
 *
 * @author tmulle
 */
public class NICUtils {

    private final static Logger LOG = LoggerFactory.getLogger(NICUtils.class);

    // List of ignored interfaces these can be any interface names you want to ignore
    private static final List<String> IGNOREDINTERFACES = Arrays.asList("awdl0", "llw0");

    // Default interface detected
    private static NetworkInterface defaultInterface;

    /**
     * The protocol family of IP address
     */
    public enum ProtocolFamily {

        /**
         * IPv4
         */
        IPV4,
        /**
         * IPv6
         */
        IPV6
    }

    static {
        defaultInterface = chooseDefaultInterface();
    }

    /**
     * Return the default interface
     *
     * @return
     */
    public static NetworkInterface getDefaultInterface() {
        return defaultInterface;
    }

    /**
     * Choose a default interface. This method returns the first interface that
     * is both "up" and supports multicast. This method chooses an interface in
     * order of preference: 1. neither loopback nor point to point ( prefer
     * interfaces with dual IP support ) 2. point to point 3. loopback
     *
     * @return the chosen interface or {@code null} if there isn't a suitable
     * default
     */
    private static NetworkInterface chooseDefaultInterface() {

        Enumeration<NetworkInterface> nifs;

        try {
            nifs = NetworkInterface.getNetworkInterfaces();
        } catch (IOException ignore) {
            // unable to enumerate network interfaces
            return null;
        }

        NetworkInterface preferred = null;
        NetworkInterface ppp = null;
        NetworkInterface loopback = null;

        while (nifs.hasMoreElements()) {
            NetworkInterface ni = nifs.nextElement();
            try {
                if (!ni.isUp() || !ni.supportsMulticast()) {
                    continue;
                }

                boolean ip4 = false, ip6 = false;
                Enumeration<InetAddress> addrs = ni.getInetAddresses();
                while (addrs.hasMoreElements()) {
                    InetAddress addr = addrs.nextElement();
                    if (!addr.isAnyLocalAddress()) {
                        if (addr instanceof Inet4Address) {
                            ip4 = true;
                        } else if (addr instanceof Inet6Address) {
                            ip6 = true;
                        }
                    }
                }

                boolean isLoopback = ni.isLoopback();
                boolean isPPP = ni.isPointToPoint();
                if (!isLoopback && !isPPP) {
                    // found an interface that is not the loopback or a
                    // point-to-point interface
                    if (preferred == null) {
                        preferred = ni;
                    } else if (ip4 == true && ip6 == true) {
                        return ni;
                    }
                }
                if (ppp == null && isPPP) {
                    ppp = ni;
                }
                if (loopback == null && isLoopback) {
                    loopback = ni;
                }

            } catch (IOException skip) {
            }
        }

        if (preferred != null) {
            return preferred;
        } else {
            return (ppp != null) ? ppp : loopback;
        }
    }

    // Returns if interface is up or false if error
    private static final Predicate<NetworkInterface> isUp = iface -> {
        try {
            return iface.isUp();
        } catch (SocketException e) {
            LOG.error("Couldn't check active status for interface {}...ignoring", iface, e);
        }

        return false;
    };

    // Returns if interface is loopback or false if error
    private static final Predicate<NetworkInterface> isNotLoopback = iface -> {
        try {
            return !iface.isLoopback();
        } catch (SocketException e) {
            LOG.error("Couldn't check loopback status for interface {}...ignoring", iface, e);
        }

        return false;
    };

    // Returns if interface is NOT virtual
    private static final Predicate<NetworkInterface> isNotVirtual = iface -> !iface.isVirtual();

    // Returns if interface is NOT point-to-point
    private static final Predicate<NetworkInterface> isNotPointToPoint = iface -> {
        try {
            return !iface.isPointToPoint();
        } catch (SocketException e) {
            LOG.error("Couldn't check point-to-point status for interface {}...ignoring", iface, e);
        }

        return false;
    };

    // Checks if interface is to be ignore
    private static final Predicate<NetworkInterface> isNotIgnored = iface -> IGNOREDINTERFACES.stream().noneMatch(iface.getName()::equals);

    // Combines ALL the predicates into one for ease of use
    private static final Predicate<NetworkInterface> allNetworkInterfaceChecks = isUp.and(isNotLoopback).and(isNotVirtual).and(isNotIgnored).and(isNotPointToPoint);

    /**
     * Checks if an InetAddress is allowed based on the passed in params
     * 
     * @param allowedIPv4
     * @param allowedIPv6
     * @return 
     */
    private static Predicate<InetAddress> isAllowedByIPFamily(boolean allowedIPv4, boolean allowedIPv6) {
        return address -> (allowedIPv4 && address instanceof Inet4Address) || (allowedIPv6 && address instanceof Inet6Address);
    }

    /**
     * Parse an InetAddress from a string
     *
     * @param addr Address to parse
     * @return InetAddress parsed or InetAddress for '0.0.0.0'
     */
    public static InetAddress parseAddress(String addr) {
        Objects.requireNonNull(addr, "Address cannot be null");
        try {
            return InetAddress.getByName(addr);
        } catch (UnknownHostException | RuntimeException e) {
            try {
                return InetAddress.getByAddress(new byte[]{0, 0, 0, 0});
            } catch (UnknownHostException | RuntimeException ee) {
                return InetAddress.getLoopbackAddress();
            }
        }
    }

    /**
     * Return the type
     *
     * @param address
     * @return
     */
    public static ProtocolFamily getProtocolFamily(InetAddress address) {
        Objects.requireNonNull(address, "Address cannot be null");
        return (address instanceof Inet4Address) ? ProtocolFamily.IPV4 : ProtocolFamily.IPV6;
    }

    /**
     * Return Network interface for given name (i.e lo, ETH0, etc)
     *
     * @param name
     * @return
     * @throws IllegalArgumentException if interface not found
     */
    public static NetworkInterface getInterfaceForName(String name) {
        Objects.requireNonNull(name, "Name cannot be null");
        try {
            return NetworkInterface.getByName(name);
        } catch (SocketException e) {
            throw new IllegalArgumentException("Couldn't find interface [" + name + "]", e);
        }
    }

    /**
     * Returns all active interfaces on the system, excluding virtual, loopback,
     * p2p If we can't check an interfaces status then we skip it and return
     * what we can
     *
     * @return Unmodifiable list of active interfaces on the system
     * @throws IllegalStateException if interfaces couldn't be read
     */
    public static List<NetworkInterface> getActiveInterfaces() {

        try {
            Enumeration<NetworkInterface> nets = NetworkInterface.getNetworkInterfaces();

            return Collections.list(nets)
                    .stream()
                    .filter(isUp)
                    .filter(isNotPointToPoint)
                    .filter(isNotVirtual)
                    .filter(isNotLoopback)
                    .filter(isNotIgnored)
                    .collect(Collectors.toUnmodifiableList());

        } catch (SocketException e) {
            throw new IllegalStateException("Trouble building list of interfaces", e);
        }
    }

    /**
     * Returns all active interfaces on the system, excluding virtual, loopback,
     * p2p If we can't check an interfaces status then we skip it and return
     * what we can
     *
     * @param interfaceName Name of interface (ie. "eth0")
     * @return Network interface
     * @throws IllegalArgumentException if interface not found
     * @throws IllegalStateException if interface is either one of these
     * condition [inactive, point-to-point, virtual, loopback, or ignored]
     */
    public static NetworkInterface getActiveInterface(String interfaceName) {

        NetworkInterface iface = getInterfaceForName(interfaceName);
        if (allNetworkInterfaceChecks.test(iface)) {
            return iface;
        } else {
            throw new IllegalStateException("Interface " + interfaceName + " is either one of these condition [inactive, point-to-point, virtual, loopback, or ignored]");
        }
    }

    /**
     * Get addresses for the name interface and by protocol
     *
     * @param family ProtocolFamily IPv4 or IPv6
     * @param interfaceName Name of interface (i.e lo, eth0, etc)
     * @return Unmodifiable list of address
     * @throws IllegalArgumentException if interface not found or if invalid
     * protocol value
     * @throws NullPointerException if missing required arguments
     */
    public static List<InetAddress> getInetAddressesByProtocolFamily(ProtocolFamily family, String interfaceName) {
        Objects.requireNonNull(family, "Protocol family cannot be null");
        Objects.requireNonNull(interfaceName, "Interface name cannot be null");

        // If found, return list of address that are mappable to the protocol family
        return getInetAddressesByProtocolFamily(family, getInterfaceForName(interfaceName));
    }

    /**
     * Get addresses for the name interface and by protocol
     *
     * @param family ProtocolFamily IPv4 or IPv6
     * @param networkInterface Network Interface
     * @return Unmodifiable list of address or empty if any errors
     * @throws IllegalArgumentException if invalid protocol value
     * @throws NullPointerException if missing required arguments
     */
    public static List<InetAddress> getInetAddressesByProtocolFamily(ProtocolFamily family, NetworkInterface networkInterface) {
        Objects.requireNonNull(family, "Protocol family cannot be null");
        Objects.requireNonNull(networkInterface, "Network interface cannot be null");

        // Used for the filter later
        Predicate<InterfaceAddress> checker;
        switch (family) {
            case IPV4:
                checker = interfaceAddress -> interfaceAddress.getAddress() instanceof Inet4Address;
                break;
            case IPV6:
                checker = interfaceAddress -> interfaceAddress.getAddress() instanceof Inet6Address;
                break;
            default:
                throw new IllegalArgumentException("Unsupported protocol family: " + family);
        }

        // Check for match
        return networkInterface.getInterfaceAddresses()
                .stream()
                .filter(checker)
                .map(InterfaceAddress::getAddress)
                .collect(Collectors.toUnmodifiableList());

    }

    /**
     * Get all allowed InetAddress for either all or specific interface based on
     * the flags
     *
     * @param allowIPv4 Allow IP4 address
     * @param allowIPv6 Allow IP6 address
     * @param networkInterfaceName Network interface name (ie. "eth0") or null
     * for ALL active found on system
     * @return Unmodifiable set of addresses
     * @throws IllegalArgumentException if interface not found
     */
    public static Set<InetAddress> getAllAllowedLocalAddresses(boolean allowIPv4, boolean allowIPv6, String networkInterfaceName) {

        // Only use the specified network interface
        if (networkInterfaceName != null && !networkInterfaceName.isEmpty()) {

            // Get the interface name
            NetworkInterface networkInterface = getInterfaceForName(networkInterfaceName);

            // filter the address
            return networkInterface.getInterfaceAddresses()
                    .stream()
                    .map(InterfaceAddress::getAddress)
                    .filter(isAllowedByIPFamily(allowIPv4, allowIPv6))
                    .collect(Collectors.toSet());

        } else { // Use all interfaces

            // Filter all active interfaces by InetAddress
            return getActiveInterfaces()
                    .stream()
                    .map(iface -> iface.getInterfaceAddresses())
                    .flatMap(Collection::stream)
                    .map(InterfaceAddress::getAddress)
                    .filter(isAllowedByIPFamily(allowIPv4, allowIPv6))
                    .collect(Collectors.toUnmodifiableSet());
        }
    }
}
