package com.sm0tnt.pfsense.logs.decoders;

import com.fasterxml.jackson.databind.node.ObjectNode;

public abstract class FilterLog {

	/**
	 * @param n The node to write to. If null, a new node will be created.
	 * @return the information in this object put into a ObjectNode.
	 */
	public abstract ObjectNode toObjectNode(ObjectNode n);

	/**
	 * @return the information in this object put into a new ObjectNode.
	 */
	public ObjectNode toObjectNode() {
		return toObjectNode(null);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public abstract String toString();

	/**
	 * 
	 * @param add   Whether to add data or not.
	 * @param sb    The string buffer to write to.
	 * @param name  The name of the value.
	 * @param value The actual value.
	 * @return the string buffer that was provided, or if that was null, a new string buffer.
	 */
	protected StringBuffer addToStringBuffer(boolean add, StringBuffer sb, String name, Object value) {
		if (sb == null)
			sb = new StringBuffer();

		if (add) {
			if (sb.length() > 0)
				sb.append("; ");
			return sb.append(name).append("=").append(value);
		} else
			return sb;
	}
}
