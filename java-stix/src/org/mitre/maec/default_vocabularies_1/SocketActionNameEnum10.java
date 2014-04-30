//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.maec.default_vocabularies_1;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for SocketActionNameEnum-1.0.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="SocketActionNameEnum-1.0">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="accept socket connection"/>
 *     &lt;enumeration value="bind address to socket"/>
 *     &lt;enumeration value="create socket"/>
 *     &lt;enumeration value="close socket"/>
 *     &lt;enumeration value="connect to socket"/>
 *     &lt;enumeration value="disconnect from socket"/>
 *     &lt;enumeration value="listen on socket"/>
 *     &lt;enumeration value="send data on socket"/>
 *     &lt;enumeration value="receive data on socket"/>
 *     &lt;enumeration value="send data to address on socket"/>
 *     &lt;enumeration value="get host by address"/>
 *     &lt;enumeration value="get host by name"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "SocketActionNameEnum-1.0")
@XmlEnum
public enum SocketActionNameEnum10 {


    /**
     * The 'accept socket connection' value specifies the defined action of accepting a socket connection.
     * 
     */
    @XmlEnumValue("accept socket connection")
    ACCEPT_SOCKET_CONNECTION("accept socket connection"),

    /**
     * The 'bind address to socket' value specifies the defined action of binding a socket address to a socket.
     * 
     */
    @XmlEnumValue("bind address to socket")
    BIND_ADDRESS_TO_SOCKET("bind address to socket"),

    /**
     * The 'create socket' value specifies the defined action of creating a new socket.
     * 
     */
    @XmlEnumValue("create socket")
    CREATE_SOCKET("create socket"),

    /**
     * The 'close socket' value specifies the defined action of closing an existing socket.
     * 
     */
    @XmlEnumValue("close socket")
    CLOSE_SOCKET("close socket"),

    /**
     * The 'connect to socket' value specifies the defined action of connecting to an existing socket.
     * 
     */
    @XmlEnumValue("connect to socket")
    CONNECT_TO_SOCKET("connect to socket"),

    /**
     * The 'disconnect from socket' value specifies the defined action of disconnecting from an existing socket.
     * 
     */
    @XmlEnumValue("disconnect from socket")
    DISCONNECT_FROM_SOCKET("disconnect from socket"),

    /**
     * The 'listen on socket' value specifies the defined action of listening on an existing socket.
     * 
     */
    @XmlEnumValue("listen on socket")
    LISTEN_ON_SOCKET("listen on socket"),

    /**
     * The 'send data on socket' value specifies the defined action of sending data on an existing, connected socket.
     * 
     */
    @XmlEnumValue("send data on socket")
    SEND_DATA_ON_SOCKET("send data on socket"),

    /**
     * The 'receive data on socket' value specifies the defined action of receiving data on an existing socket.
     * 
     */
    @XmlEnumValue("receive data on socket")
    RECEIVE_DATA_ON_SOCKET("receive data on socket"),

    /**
     * The 'send data to address on socket' value specifies the defined action of sending data to a specified IP address on an existing, unconnected socket.
     * 
     */
    @XmlEnumValue("send data to address on socket")
    SEND_DATA_TO_ADDRESS_ON_SOCKET("send data to address on socket"),

    /**
     * The 'get host by address' value specifies the defined action of getting information on a host from a local or remote host database by its IP address.
     * 
     */
    @XmlEnumValue("get host by address")
    GET_HOST_BY_ADDRESS("get host by address"),

    /**
     * The 'get host by name' value specifies the defined action of getting information on a host from a local or remote host database by its name.
     * 
     */
    @XmlEnumValue("get host by name")
    GET_HOST_BY_NAME("get host by name");
    private final String value;

    SocketActionNameEnum10(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static SocketActionNameEnum10 fromValue(String v) {
        for (SocketActionNameEnum10 c: SocketActionNameEnum10 .values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
