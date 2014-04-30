//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.cybox.objects;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElementRef;
import javax.xml.bind.annotation.XmlElementRefs;
import javax.xml.bind.annotation.XmlType;
import org.mitre.cybox.common_2.CipherType;
import org.mitre.cybox.common_2.IntegerObjectPropertyType;
import org.mitre.cybox.common_2.StringObjectPropertyType;


/**
 * The ArchiveFileObjectType type is intended to characterize archive files.
 * 
 * <p>Java class for ArchiveFileObjectType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ArchiveFileObjectType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://cybox.mitre.org/objects#FileObject-2}FileObjectType">
 *       &lt;sequence>
 *         &lt;element name="Archive_Format" type="{http://cybox.mitre.org/objects#ArchiveFileObject-1}ArchiveFileFormatType" minOccurs="0"/>
 *         &lt;element name="Version" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="File_Count" type="{http://cybox.mitre.org/common-2}IntegerObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Encryption_Algorithm" type="{http://cybox.mitre.org/common-2}CipherType" minOccurs="0"/>
 *         &lt;element name="Decryption_Key" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Comment" type="{http://cybox.mitre.org/common-2}StringObjectPropertyType" minOccurs="0"/>
 *         &lt;element name="Archived_File" type="{http://cybox.mitre.org/objects#FileObject-2}FileObjectType" maxOccurs="unbounded" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ArchiveFileObjectType", namespace = "http://cybox.mitre.org/objects#ArchiveFileObject-1", propOrder = {
    "rest"
})
public class ArchiveFileObjectType
    extends FileObjectType
{

    @XmlElementRefs({
        @XmlElementRef(name = "Archive_Format", namespace = "http://cybox.mitre.org/objects#ArchiveFileObject-1", type = JAXBElement.class, required = false),
        @XmlElementRef(name = "Version", namespace = "http://cybox.mitre.org/objects#ArchiveFileObject-1", type = JAXBElement.class, required = false),
        @XmlElementRef(name = "Archived_File", namespace = "http://cybox.mitre.org/objects#ArchiveFileObject-1", type = JAXBElement.class, required = false),
        @XmlElementRef(name = "Encryption_Algorithm", namespace = "http://cybox.mitre.org/objects#ArchiveFileObject-1", type = JAXBElement.class, required = false),
        @XmlElementRef(name = "Decryption_Key", namespace = "http://cybox.mitre.org/objects#ArchiveFileObject-1", type = JAXBElement.class, required = false),
        @XmlElementRef(name = "Comment", namespace = "http://cybox.mitre.org/objects#ArchiveFileObject-1", type = JAXBElement.class, required = false),
        @XmlElementRef(name = "File_Count", namespace = "http://cybox.mitre.org/objects#ArchiveFileObject-1", type = JAXBElement.class, required = false)
    })
    protected List<JAXBElement<?>> rest;

    /**
     * Gets the rest of the content model. 
     * 
     * <p>
     * You are getting this "catch-all" property because of the following reason: 
     * The field name "EncryptionAlgorithm" is used by two different parts of a schema. See: 
     * line 42 of file:/media/sf_threat/contrib/java-stix/stix/cybox/objects/Archive_File_Object.xsd
     * line 131 of file:/media/sf_threat/contrib/java-stix/stix/cybox/objects/File_Object.xsd
     * <p>
     * To get rid of this property, apply a property customization to one 
     * of both of the following declarations to change their names: 
     * Gets the value of the rest property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the rest property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getRest().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link JAXBElement }{@code <}{@link ArchiveFileFormatType }{@code >}
     * {@link JAXBElement }{@code <}{@link StringObjectPropertyType }{@code >}
     * {@link JAXBElement }{@code <}{@link FileObjectType }{@code >}
     * {@link JAXBElement }{@code <}{@link CipherType }{@code >}
     * {@link JAXBElement }{@code <}{@link StringObjectPropertyType }{@code >}
     * {@link JAXBElement }{@code <}{@link IntegerObjectPropertyType }{@code >}
     * {@link JAXBElement }{@code <}{@link StringObjectPropertyType }{@code >}
     * 
     * 
     */
    public List<JAXBElement<?>> getRest() {
        if (rest == null) {
            rest = new ArrayList<JAXBElement<?>>();
        }
        return this.rest;
    }

}
