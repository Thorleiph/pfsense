package com.sm0tnt.pfsense.logs.decoders;

import java.io.Serializable;

import org.apache.commons.lang3.StringUtils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sm0tnt.addr.iptools.IPAddress;

public class RSysLogMessage implements Serializable {
	private static final long serialVersionUID = 3755260541573661840L;

	public static final String ADDRESS = "address";
	public static final String PORT = "port";
	public static final String RECEIVE_TIME = "receivetime";
	public static final String NANO_TIME = "receivenanotime";
	public static final String PRIORITY = "priority";
	public static final String TIME = "time";
	public static final String PROCESS = "process";
	public static final String PID = "pid";
	public static final String MESSAGE = "message";
	public static final String PAYLOAD = "payload";
	public static final String HOSTNAME = "hostname";

	public static final String SERVICE_UNHANDLED = "service unhandled";
	public static final String SERVICE_NO_PROCESS = "no process";

	// public static final String SERVICE_APACHE2 = "apache2";
	// public static final String SERVICE_APACHE_ACCESS = "apache-access";

	public static final String SERVICE_APACHE2_ERROR = "apache2-error";
	public static final String SERVICE_APACHE2_REDIRECT_ERROR = "apache2-redirect-error";
	public static final String SERVICE_APACHE2_COMBINED = "apache2-combined";
	public static final String SERVICE_APACHE2_VHOST_COMBINED = "apache2-vhost_combined";

	public static final String SERVICE_NGINX = "nginx";
	public static final String SERVICE_CRON = "cron";
	public static final String SERVICE_DHCPD = "dhcpd";
	public static final String SERVICE_DHCPLEASES = "dhcpleases";
	public static final String SERVICE_FILTERLOG = "filterlog";
	public static final String SERVICE_NTPD = "ntpd";
	public static final String SERVICE_SSHD = "sshd";
	public static final String SERVICE_SYSTEMD = "systemd";
	public static final String SERVICE_SYSTEMD_LOGIND = "systemd-logind";
	public static final String SERVICE_SYSTEMD_RESOLVED = "systemd-resolved";
	public static final String SERVICE_UNBOUND = "unbound";
	public static final String SERVICE_TRANSMISSION_DAEMON = "transmission-daemon";
	public static final String SERVICE_HTTPD = "httpd";
	public static final String SERVICE_KERNEL = "kernel";
	public static final String SERVICE_SYSTEMD_UDEVD = "systemd-udevd";

	public static final String SERVICE_POSTFIX = "postfix";
	public static final String SERVICE_POSTFIX_SMTPD = "postfix/smtpd";
	public static final String SERVICE_POSTFIX_ANVIL = "postfix/anvil";
	public static final String SERVICE_POSTFIX_SMTPS_SMTPD = "postfix/smtps/smtpd";
	public static final String SERVICE_POSTFIX_QMGR = "postfix/qmgr";

	public static final String SERVICE_MOTD = "motd";
	public static final String SERVICE_50_MOTD_NEWS = "50-motd-news";

	public static final String SERVICE_RSYNC = "rsync";
	public static final String SERVICE_SASLAUTHD = "saslauthd";
	public static final String SERVICE_DHCLIENT = "dhclient";
	public static final String SERVICE_DOCKERD = "dockerd";
	public static final String SERVICE_SYSTEMD_TIMESYNCD = "systemd-timesyncd";
	public static final String SERVICE_SYSTEMD_NETWORKD = "systemd-networkd";
	public static final String SERVICE_DOVECOT = "dovecot";
	public static final String SERVICE_SNAPD = "snapd";
	public static final String SERVICE_SYSLOG_NG = "syslog-ng";
	public static final String SERVICE_RNGD = "rngd";
	public static final String SERVICE_RSYSLOGD = "rsyslogd";
	public static final String SERVICE_PID = PID;
	public static final String SERVICE_SMARTD = "smartd";
	public static final String SERVICE_NETWORKMANAGER = "networkmanager";
	public static final String SERVICE_NM_DISPATCHER = "nm-dispatcher";
	public static final String SERVICE_DBUS = "dbus";
	public static final String SERVICE_CHARON = "charon";
	public static final String SERVICE_PHP_CGI = "php-cgi";
	public static final String SERVICE_DHCPCD = "dhcpcd";
	public static final String SERVICE_AVAHI_DAEMON = "avahi-daemon";
	public static final String SERVICE_NAMED = "named";
	public static final String SERVICE_EXIM4 = "exim4";
	public static final String SERVICE_DPINGER = "dpinger";

	public static final String SERVICE_ZFS = "zfs";
	public static final String SERVICE_ZFSD = "zfsd";
	public static final String SERVICE_FSTRIM = "fstrim";
	public static final String SERVICE_SYSTEMD_TMPFILES = "systemd-tmpfiles";

	public static final String USR_SBIN_CRON = "/usr/sbin/cron";

	public static final String FAIL2BAN = "fail2ban";

	private IPAddress address;
	private int port;
	private long receiveNanoTime;
	private int priority;
	private long time;
	private String process;
	private String hostname;
	private Integer pid;
	private RSysLogPayload payload;

	private transient boolean flHeaderSearched;
	private transient FilterLogHeader flHeader;

	private transient boolean flv4Searched;
	private transient FilterLogIPv4 flv4;

	private transient boolean flv6Searched;
	private transient FilterLogIPv6 flv6;

	private transient boolean flTCPSearched;
	private transient FilterLogTCP flTCP;

	private transient boolean flUDPSearched;
	private transient FilterLogUDP flUDP;

	// private transient boolean flICMPSearched;
	// private transient FilterLogICMP flICMP;

	/**
	 * Constructor.
	 * 
	 * @param address         The source address.
	 * @param port            The port.
	 * @param receiveNanoTime The receive time in nanoseconds.
	 * @param priority        The priority.
	 * @param time            The time in milliseconds.
	 * @param hostname        The hostname.
	 * @param process         The process name.
	 * @param pid             The process id.
	 * @param payload         The payload.
	 */
	public RSysLogMessage(IPAddress address, int port, long receiveNanoTime, int priority, long time, String hostname, String process, Integer pid, RSysLogPayload payload) {
		this.address = address;
		this.port = port;
		this.receiveNanoTime = receiveNanoTime;
		this.priority = priority;
		this.time = time;
		this.hostname = hostname;
		this.process = process;
		this.pid = pid;
		this.payload = payload;
	}

	/**
	 * @param newPayload The new payload.
	 * @return a copy of this message but with a different payload.
	 */
	public RSysLogMessage withNewPayload(RSysLogPayload newPayload) {
		return new RSysLogMessage(this.address, this.port, this.receiveNanoTime, this.priority, this.time, this.hostname, this.process, this.pid, newPayload);
	}

	/**
	 * @return the address
	 */
	public IPAddress getAddress() {
		return address;
	}

	/**
	 * @return the port
	 */
	public int getPort() {
		return port;
	}

	/**
	 * @return the receiveNanoTime
	 */
	public long getReceiveNanoTime() {
		return receiveNanoTime;
	}

	/**
	 * @return the priority
	 */
	public int getPriority() {
		return priority;
	}

	/**
	 * @return the time
	 */
	public long getTime() {
		return time;
	}

	/**
	 * @return the process
	 */
	public String getProcess() {
		return process;
	}

	/**
	 * @return the hostname
	 */
	public String getHostname() {
		return hostname;
	}

	/**
	 * @return the pid
	 */
	public Integer getPid() {
		return pid;
	}

	/**
	 * @return the payload
	 */
	public RSysLogPayload getPayload() {
		return payload;
	}

	/**
	 * @return the FilterLogStack, or null if payload is of wrong type or null.
	 */
	public FilterLogStack getFilterLogStack() {
		if (this.payload != null && this.payload instanceof FilterLogStack)
			return (FilterLogStack) this.payload;
		else
			return null;
	}

	private <T extends FilterLog> T getFilterLog(Class<T> type) {
		FilterLogStack stack = getFilterLogStack();
		for (FilterLog fl : stack) {
			if (type.isInstance(fl))
				return type.cast(fl);
		}

		return null;
	}

	private FilterLogHeader getFilterLogHeader() {
		if (this.flHeaderSearched)
			return this.flHeader;
		this.flHeaderSearched = true;
		return this.flHeader = getFilterLog(FilterLogHeader.class);
	}

	private FilterLogIPv4 getFilterLogIPv4() {
		if (this.flv4Searched)
			return this.flv4;
		this.flv4Searched = true;
		return this.flv4 = getFilterLog(FilterLogIPv4.class);
	}

	private FilterLogIPv6 getFilterLogIPv6() {
		if (this.flv6Searched)
			return this.flv6;
		this.flv6Searched = true;
		return this.flv6 = getFilterLog(FilterLogIPv6.class);
	}

	private FilterLogTCP getFilterLogTCP() {
		if (this.flTCPSearched)
			return this.flTCP;

		this.flTCPSearched = true;
		return (this.flTCP = getFilterLog(FilterLogTCP.class));
	}

	private FilterLogUDP getFilterLogUDP() {
		if (this.flUDPSearched)
			return this.flUDP;
		this.flUDPSearched = true;
		return this.flUDP = getFilterLog(FilterLogUDP.class);
	}

	/**
	 * @return the source address, or null if none exists.
	 */
	public IPAddress getSourceAddress() {
		FilterLogIPv4 v4 = getFilterLogIPv4();
		if (v4 != null)
			return v4.getSrcAddr();
		FilterLogIPv6 v6 = getFilterLogIPv6();
		if (v6 != null)
			return v6.getSrcAddr();
		return null;
	}

	/**
	 * @return the rule number.
	 */
	public int getRuleNumber() {
		FilterLogHeader hdr = getFilterLogHeader();
		if (hdr != null)
			return hdr.getRuleNumber();
		else
			return -1;
	}

	/**
	 * @return the destination address, or null if none exists.
	 */
	public IPAddress getDestinationAddress() {
		FilterLogIPv4 v4 = getFilterLogIPv4();
		if (v4 != null)
			return v4.getDestAddr();
		FilterLogIPv6 v6 = getFilterLogIPv6();
		if (v6 != null)
			return v6.getDestAddr();
		return null;
	}

	/**
	 * @return the reason.
	 */
	public String getReason() {
		FilterLogHeader hdr = getFilterLogHeader();
		if (hdr != null)
			return hdr.getReason();
		return null;
	}

	/**
	 * @return the action.
	 */
	public String getAction() {
		FilterLogHeader hdr = getFilterLogHeader();
		if (hdr != null)
			return hdr.getAction();
		return null;
	}

	/**
	 * @return the real interface name.
	 */
	public String getRealInterface() {
		FilterLogHeader hdr = getFilterLogHeader();
		if (hdr != null)
			return hdr.getRealInterface();
		return null;
	}

	/**
	 * @return the direction of the traffic.
	 */
	public String getDirection() {
		FilterLogHeader hdr = getFilterLogHeader();
		if (hdr != null)
			return hdr.getDirection();
		return null;
	}

	/**
	 * @return the protocol text.
	 */
	public String getProtocolText() {
		FilterLogIPv4 v4 = getFilterLogIPv4();
		if (v4 != null)
			return v4.getProtocolText();
		FilterLogIPv6 v6 = getFilterLogIPv6();
		if (v6 != null)
			return v6.getProtocolText();
		return null;
	}

	/**
	 * @return the protocol id.
	 */
	public int getProtocolId() {
		FilterLogIPv4 v4 = getFilterLogIPv4();
		if (v4 != null)
			return v4.getProtocolId();
		FilterLogIPv6 v6 = getFilterLogIPv6();
		if (v6 != null)
			return v6.getProtocolId();
		return -1;
	}

	/**
	 * @return the TCP or UDP source port, -1 if neither exists.
	 */
	public int getSourcePort() {
		FilterLogUDP udp = getFilterLogUDP();
		if (udp != null)
			return udp.getSrcPort();
		FilterLogTCP tcp = getFilterLogTCP();
		if (tcp != null)
			return tcp.getSrcPort();
		return -1;
	}

	/**
	 * @return the TCP or UDP destination port, -1 if neither exists.
	 */
	public int getDestinationPort() {
		FilterLogUDP udp = getFilterLogUDP();
		if (udp != null)
			return udp.getDstPort();
		FilterLogTCP tcp = getFilterLogTCP();
		if (tcp != null)
			return tcp.getDstPort();
		return -1;
	}

	/**
	 * 
	 * @param n The object node to be written to. If null, a new one is created.
	 * @return either the provided node or a new with information from this object.
	 */
	public ObjectNode toObjectNode(ObjectNode n) {
		if (n == null)
			n = new ObjectMapper().createObjectNode();

		n.put(ADDRESS, this.address.toString());
		n.put(PORT, this.port);
		n.put(NANO_TIME, this.receiveNanoTime);
		n.put(PRIORITY, this.priority);
		n.put(TIME, this.time);
		n.put(PROCESS, this.process);
		if (StringUtils.isNotBlank(this.hostname))
			n.put(HOSTNAME, this.hostname);
		if (this.pid != null)
			n.put(PID, this.pid);
		if (this.payload != null)
			n.set(PAYLOAD, this.payload.toObjectNode(null));

		return n;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		StringBuffer result = new StringBuffer();
		result.append(getClass().getSimpleName()).append("(");

		result.append(ADDRESS).append("=").append(this.address);
		result.append("; ").append(PORT).append("=").append(this.port);
		result.append("; ").append(NANO_TIME).append("=").append(this.receiveNanoTime);
		result.append("; ").append(PRIORITY).append("=").append(this.priority);
		result.append("; ").append(TIME).append("=").append(this.time);
		result.append("; ").append(PROCESS).append("=").append(this.process);
		if (StringUtils.isNotBlank(this.hostname))
			result.append("; ").append(HOSTNAME).append("=").append(this.hostname);
		if (this.pid != null)
			result.append("; ").append(PID).append("=").append(this.pid);
		if (this.payload != null)
			result.append("; ").append(PAYLOAD).append("=").append(this.payload);

		result.append(")");
		return result.toString();
	}
}
