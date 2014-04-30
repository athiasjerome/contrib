//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.cybox.objects;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for RegistryHiveEnum.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="RegistryHiveEnum">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="HKEY_CLASSES_ROOT"/>
 *     &lt;enumeration value="HKEY_CURRENT_CONFIG"/>
 *     &lt;enumeration value="HKEY_CURRENT_USER"/>
 *     &lt;enumeration value="HKEY_LOCAL_MACHINE"/>
 *     &lt;enumeration value="HKEY_USERS"/>
 *     &lt;enumeration value="HKEY_CURRENT_USER_LOCAL_SETTINGS"/>
 *     &lt;enumeration value="HKEY_PERFORMANCE_DATA"/>
 *     &lt;enumeration value="HKEY_PERFORMANCE_NLSTEXT"/>
 *     &lt;enumeration value="HKEY_PERFORMANCE_TEXT"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "RegistryHiveEnum", namespace = "http://cybox.mitre.org/objects#WinRegistryKeyObject-2")
@XmlEnum
public enum RegistryHiveEnum {


    /**
     * Registry entries subordinate to this key define types (or classes) of documents and the properties associated with those types. Shell and COM applications use the information stored under this key.
     * 
     */
    HKEY_CLASSES_ROOT,

    /**
     * Contains information about the current hardware profile of the local computer system. The information under HKEY_CURRENT_CONFIG describes only the differences between the current hardware configuration and the standard configuration.
     * 
     */
    HKEY_CURRENT_CONFIG,

    /**
     * Registry entries subordinate to this key define the preferences of the current user. These preferences include the settings of environment variables, data about program groups, colors, printers, network connections, and application preferences. This key makes it easier to establish the current user's settings; the key maps to the current user's branch in HKEY_USERS.
     * 
     */
    HKEY_CURRENT_USER,

    /**
     * Registry entries subordinate to this key define the physical state of the computer, including data about the bus type, system memory, and installed hardware and software.
     * 
     */
    HKEY_LOCAL_MACHINE,

    /**
     * Registry entries subordinate to this key define the default user configuration for new users on the local computer and the user configuration for the current user.
     * 
     */
    HKEY_USERS,

    /**
     * Registry entries subordinate to this key define preferences of the current user that are local to the machine. These entries are not included in the per-user registry portion of a roaming user profile.
     * 
     */
    HKEY_CURRENT_USER_LOCAL_SETTINGS,

    /**
     * Registry entries subordinate to this key allow you to access performance data. The data is not actually stored in the registry; the registry functions cause the system to collect the data from its source.
     * 
     */
    HKEY_PERFORMANCE_DATA,

    /**
     * Registry entries subordinate to this key reference the text strings that describe counters in the local language of the area in which the computer system is running. These entries are not available to Regedit.exe and Regedt32.exe.
     * 
     */
    HKEY_PERFORMANCE_NLSTEXT,

    /**
     * Registry entries subordinate to this key reference the text strings that describe counters in US English. These entries are not available to Regedit.exe and Regedt32.exe.
     * 
     */
    HKEY_PERFORMANCE_TEXT;

    public String value() {
        return name();
    }

    public static RegistryHiveEnum fromValue(String v) {
        return valueOf(v);
    }

}
