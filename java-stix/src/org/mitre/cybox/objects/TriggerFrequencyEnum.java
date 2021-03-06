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
 * <p>Java class for TriggerFrequencyEnum.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="TriggerFrequencyEnum">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="TASK_TIME_TRIGGER_ONCE"/>
 *     &lt;enumeration value="TASK_EVENT_TRIGGER_ON_IDLE"/>
 *     &lt;enumeration value="TASK_EVENT_TRIGGER_AT_SYSTEMSTART"/>
 *     &lt;enumeration value="TASK_EVENT_TRIGGER_AT_LOGON"/>
 *     &lt;enumeration value="TASK_TIME_TRIGGER_DAILY"/>
 *     &lt;enumeration value="TASK_TIME_TRIGGER_WEEKLY"/>
 *     &lt;enumeration value="TASK_TIME_TRIGGER_MONTHLYDATE"/>
 *     &lt;enumeration value="TASK_TIME_TRIGGER_MONTHLYDOW"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "TriggerFrequencyEnum", namespace = "http://cybox.mitre.org/objects#WinTaskObject-2")
@XmlEnum
public enum TriggerFrequencyEnum {


    /**
     * Trigger is set to run the task a single time.
     * 
     */
    TASK_TIME_TRIGGER_ONCE,

    /**
     * Trigger is set to run the task if the system remains idle for the amount of time specified by the idle wait time of the task.
     * 
     */
    TASK_EVENT_TRIGGER_ON_IDLE,

    /**
     * Trigger is set to run the task at system startup.
     * 
     */
    TASK_EVENT_TRIGGER_AT_SYSTEMSTART,

    /**
     * Trigger is set to run the task when a user logs on.
     * 
     */
    TASK_EVENT_TRIGGER_AT_LOGON,

    /**
     * Trigger is set to run the task on a daily interval.
     * 
     */
    TASK_TIME_TRIGGER_DAILY,

    /**
     * Trigger is set to run the work item on specific days of a specific week of a specific month.
     * 
     */
    TASK_TIME_TRIGGER_WEEKLY,

    /**
     * Trigger is set to run the task on a specific day(s) of the month.
     * 
     */
    TASK_TIME_TRIGGER_MONTHLYDATE,

    /**
     * Trigger is set to run the task on specific days, weeks, and months.
     * 
     */
    TASK_TIME_TRIGGER_MONTHLYDOW;

    public String value() {
        return name();
    }

    public static TriggerFrequencyEnum fromValue(String v) {
        return valueOf(v);
    }

}
