package com.sm0tnt.pfsense.logs.decoders;

import java.util.Date;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collector;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sm0tnt.addr.iptools.IPAddress;

public class UnboundDecoder extends ProcessFunction<RSysLogMessage, RSysLogMessage> {
	private static final long serialVersionUID = 2585356952816554693L;

	private static final Logger logger = LogManager.getLogger(UnboundDecoder.class.getSimpleName());

	public static final String QUERY = "query";
	public static final String INFO = "info";
	public static final String DEBUG = "debug";
	public static final String REPLY = "reply";
	public static final String ERROR = "error";

	public static final String CLIENT_IP = "clientip";
	public static final String QNAME = "qname";
	public static final String TYPE = "type";
	public static final String CLASS = "class";
	public static final String R_CODE = "rcode";
	public static final String DUR_TV_SEC_USEC = "dur_tv_sec_usec";
	public static final String CACHED = "cached";
	public static final String PKT_LEN = "pktlen";

	public static final String SERVFAIL = "SERVFAIL";

	private Pattern splitPattern;

	private TreeSet<String> names;

	private ObjectMapper mapper;

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void processElement(RSysLogMessage input, ProcessFunction<RSysLogMessage, RSysLogMessage>.Context context, Collector<RSysLogMessage> output) throws Exception {
		RSysLogPayload result = null;
		RSysLogPayload tmp = input.getPayload();

		Date d = new Date(input.getTime());

		if (this.names == null)
			this.names = new TreeSet<>();

		if (tmp instanceof StringPayload) {
			String payload = tmp.toString();

			if (StringUtils.isNotBlank(payload)) {
				if (this.splitPattern == null)
					this.splitPattern = Pattern.compile("(\\[\\d{1,}\\:\\d\\])(?: )(\\S{1,})(?:\\: )(.*)");

				Matcher matcher = this.splitPattern.matcher(payload);

				if (matcher.matches() && matcher.groupCount() == 3) {
					String messageType = matcher.group(2);
					String message = matcher.group(3);

					switch (messageType) {
					case QUERY: {
						String parts[] = message.split(" ");

						if (parts.length == 4) {
							IPAddress clientIp = IPAddress.fromString(parts[0]);
							String qname = parts[1];
							String type = parts[2].toLowerCase();
							String clazz = parts[3].toLowerCase();

							// logger.debug(d + ":\t" + qname + "\t" + type + "\t" + clazz + "\t\t" + message);
						} else {
							// logger.debug("########\t" + d + "\t\t" + message);
						}

						break;
					}

					case INFO: {
						// logger.debug(messageType + ":\t" + message);
						break;
					}

					case DEBUG: {
						// logger.debug(messageType + ":\t" + message);
						break;
					}

					case REPLY: {
						String[] parts = message.split(" ");

						if (parts.length == 8) {
							try {
								IPAddress clientIp = IPAddress.fromString(parts[0]);
								String qname = parts[1].toLowerCase();
								String type = parts[2].toLowerCase();
								String clazz = parts[3].toLowerCase();
								String rcode = parts[4].toLowerCase();
								Double dur_tv_sec_usec = Double.parseDouble(parts[5]);
								boolean cached = !parts[6].equals("0");
								int pktlen = Integer.parseInt(parts[7]);

								boolean inAddrARPA = qname.endsWith(UnboundReply.IN_ADDR_ARPA_ENDING);

								result = new UnboundReply(clientIp, qname, type, clazz, rcode, dur_tv_sec_usec, cached, pktlen);

								if (this.mapper == null)
									this.mapper = new ObjectMapper();

								UnboundReply reply = (UnboundReply) result;
								logger.debug(reply.getClientIp() + ":\t" + reply.getType() + ":\t" + reply.getRcode() + ":\t" + reply.getQname() + "\t" + reply.getDomainNameParts());
							} catch (Exception e) {
								logger.info(e.getMessage(), e);
							}
						} else {
							// logger.debug(d + ":\t" + messageType + "\t\t" + message);
						}

						break;
					}

					case ERROR: {
						// logger.debug("'" + messageType + "'" + "\t'" + message + "'");

						int p0 = message.indexOf(" ");

						if (p0 < 0)
							break;

						String errorType = message.substring(0, p0);

						p0 = message.indexOf("<");
						if (p0 < 0)
							break;

						int p1 = message.indexOf(">", p0);
						if (p1 < 0)
							break;

						String str = message.substring(p0 + 1, p1);

						p0 = str.indexOf(" ");
						if (p0 < 0)
							break;

						String domain = str.substring(0, p0).toLowerCase();
						String type = str.substring(p0);

						// logger.debug(errorType + "\t" + domain + "\t\t" + type + "\t" + message);

						break;
					}

					default: {
						// logger.debug("default:\t" + messageType + "\t" + message);
						break;
					}
					}
				}
			}
		}
	}
}
