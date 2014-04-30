//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.cybox.objects;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for UnixFileTypeEnum.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="UnixFileTypeEnum">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="regularfile"/>
 *     &lt;enumeration value="directory"/>
 *     &lt;enumeration value="socket"/>
 *     &lt;enumeration value="symboliclink"/>
 *     &lt;enumeration value="blockspecialfile"/>
 *     &lt;enumeration value="characterspecialfile"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "UnixFileTypeEnum", namespace = "http://cybox.mitre.org/objects#UnixFileObject-2")
@XmlEnum
public enum UnixFileTypeEnum {


    /**
     * Specifies a regular file, denoted in UNIX by the first dash (-) in a file with permissions -rw-r--r--.
     * 
     */
    @XmlEnumValue("regularfile")
    REGULARFILE("regularfile"),

    /**
     * Specifies a directory, denoted in UNIX by the d in a file with permissions drw-r--r--.
     * 
     */
    @XmlEnumValue("directory")
    DIRECTORY("directory"),

    /**
     * Specifies a socket, denoted in UNIX by the s in a file with permissions srw-r--r--.
     * 
     */
    @XmlEnumValue("socket")
    SOCKET("socket"),

    /**
     * Specifies a symbolic link, denoted in UNIX by the l in a file with permissions lrw-r--r--.
     * 
     */
    @XmlEnumValue("symboliclink")
    SYMBOLICLINK("symboliclink"),

    /**
     * Specifies a block device, such as /dev/sda, denoted in UNIX by the b in a file with permissions brw-rw----.
     * 
     */
    @XmlEnumValue("blockspecialfile")
    BLOCKSPECIALFILE("blockspecialfile"),

    /**
     * Specifies a character device, such as /dev/null, denoted in UNIX by the c in a file with permissions crw-------.
     * 
     */
    @XmlEnumValue("characterspecialfile")
    CHARACTERSPECIALFILE("characterspecialfile");
    private final String value;

    UnixFileTypeEnum(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static UnixFileTypeEnum fromValue(String v) {
        for (UnixFileTypeEnum c: UnixFileTypeEnum.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}