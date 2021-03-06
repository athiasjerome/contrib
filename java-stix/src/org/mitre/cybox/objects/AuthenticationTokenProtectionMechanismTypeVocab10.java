//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.cybox.objects;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;
import org.mitre.cybox.common_2.ControlledVocabularyStringType;


/**
 * The AuthenticationTokenProtectionMechanismTypeVocab is the default CybOX vocabulary for authentication token protection mechanisms, used in the AuthenticationType/Authentication_Token_Protection_Mechanism found in the Account Object schema.
 * 
 * <p>Java class for AuthenticationTokenProtectionMechanismTypeVocab-1.0 complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="AuthenticationTokenProtectionMechanismTypeVocab-1.0">
 *   &lt;simpleContent>
 *     &lt;restriction base="&lt;http://cybox.mitre.org/common-2>ControlledVocabularyStringType">
 *       &lt;attribute name="vocab_name" type="{http://www.w3.org/2001/XMLSchema}string" fixed="CybOX Default Authentication Token Protection Mechanism Types" />
 *       &lt;attribute name="vocab_reference" type="{http://www.w3.org/2001/XMLSchema}anyURI" fixed="http://cybox.mitre.org/XMLSchema/objects/Account/2.1/Account_Object.xsd#AuthenticationTokenProtectionMechanismTypeVocab-1.0" />
 *     &lt;/restriction>
 *   &lt;/simpleContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "AuthenticationTokenProtectionMechanismTypeVocab-1.0", namespace = "http://cybox.mitre.org/objects#AccountObject-2")
public class AuthenticationTokenProtectionMechanismTypeVocab10
    extends ControlledVocabularyStringType
{


}
