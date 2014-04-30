//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.cybox.objects;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * The PDFKeywordCountsType captures the occurrences of various keywords in a PDF file.
 * 
 * <p>Java class for PDFKeywordCountsType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="PDFKeywordCountsType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Page_Count" type="{http://cybox.mitre.org/objects#PDFFileObject-1}PDFKeywordCountType" minOccurs="0"/>
 *         &lt;element name="Encrypt_Count" type="{http://cybox.mitre.org/objects#PDFFileObject-1}PDFKeywordCountType" minOccurs="0"/>
 *         &lt;element name="ObjStm_Count" type="{http://cybox.mitre.org/objects#PDFFileObject-1}PDFKeywordCountType" minOccurs="0"/>
 *         &lt;element name="JS_Count" type="{http://cybox.mitre.org/objects#PDFFileObject-1}PDFKeywordCountType" minOccurs="0"/>
 *         &lt;element name="JavaScript_Count" type="{http://cybox.mitre.org/objects#PDFFileObject-1}PDFKeywordCountType" minOccurs="0"/>
 *         &lt;element name="AA_Count" type="{http://cybox.mitre.org/objects#PDFFileObject-1}PDFKeywordCountType" minOccurs="0"/>
 *         &lt;element name="OpenAction_Count" type="{http://cybox.mitre.org/objects#PDFFileObject-1}PDFKeywordCountType" minOccurs="0"/>
 *         &lt;element name="ASCIIHexDecode_Count" type="{http://cybox.mitre.org/objects#PDFFileObject-1}PDFKeywordCountType" minOccurs="0"/>
 *         &lt;element name="ASCII85Decode_Count" type="{http://cybox.mitre.org/objects#PDFFileObject-1}PDFKeywordCountType" minOccurs="0"/>
 *         &lt;element name="LZWDecode_Count" type="{http://cybox.mitre.org/objects#PDFFileObject-1}PDFKeywordCountType" minOccurs="0"/>
 *         &lt;element name="FlateDecode_Count" type="{http://cybox.mitre.org/objects#PDFFileObject-1}PDFKeywordCountType" minOccurs="0"/>
 *         &lt;element name="RunLengthDecode_Count" type="{http://cybox.mitre.org/objects#PDFFileObject-1}PDFKeywordCountType" minOccurs="0"/>
 *         &lt;element name="JBIG2Decode_Count" type="{http://cybox.mitre.org/objects#PDFFileObject-1}PDFKeywordCountType" minOccurs="0"/>
 *         &lt;element name="DCTDecode_Count" type="{http://cybox.mitre.org/objects#PDFFileObject-1}PDFKeywordCountType" minOccurs="0"/>
 *         &lt;element name="RichMedia_Count" type="{http://cybox.mitre.org/objects#PDFFileObject-1}PDFKeywordCountType" minOccurs="0"/>
 *         &lt;element name="CCITTFaxDecode_Count" type="{http://cybox.mitre.org/objects#PDFFileObject-1}PDFKeywordCountType" minOccurs="0"/>
 *         &lt;element name="Launch_Count" type="{http://cybox.mitre.org/objects#PDFFileObject-1}PDFKeywordCountType" minOccurs="0"/>
 *         &lt;element name="XFA_Count" type="{http://cybox.mitre.org/objects#PDFFileObject-1}PDFKeywordCountType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "PDFKeywordCountsType", namespace = "http://cybox.mitre.org/objects#PDFFileObject-1", propOrder = {
    "pageCount",
    "encryptCount",
    "objStmCount",
    "jsCount",
    "javaScriptCount",
    "aaCount",
    "openActionCount",
    "asciiHexDecodeCount",
    "ascii85DecodeCount",
    "lzwDecodeCount",
    "flateDecodeCount",
    "runLengthDecodeCount",
    "jbig2DecodeCount",
    "dctDecodeCount",
    "richMediaCount",
    "ccittFaxDecodeCount",
    "launchCount",
    "xfaCount"
})
public class PDFKeywordCountsType {

    @XmlElement(name = "Page_Count")
    protected PDFKeywordCountType pageCount;
    @XmlElement(name = "Encrypt_Count")
    protected PDFKeywordCountType encryptCount;
    @XmlElement(name = "ObjStm_Count")
    protected PDFKeywordCountType objStmCount;
    @XmlElement(name = "JS_Count")
    protected PDFKeywordCountType jsCount;
    @XmlElement(name = "JavaScript_Count")
    protected PDFKeywordCountType javaScriptCount;
    @XmlElement(name = "AA_Count")
    protected PDFKeywordCountType aaCount;
    @XmlElement(name = "OpenAction_Count")
    protected PDFKeywordCountType openActionCount;
    @XmlElement(name = "ASCIIHexDecode_Count")
    protected PDFKeywordCountType asciiHexDecodeCount;
    @XmlElement(name = "ASCII85Decode_Count")
    protected PDFKeywordCountType ascii85DecodeCount;
    @XmlElement(name = "LZWDecode_Count")
    protected PDFKeywordCountType lzwDecodeCount;
    @XmlElement(name = "FlateDecode_Count")
    protected PDFKeywordCountType flateDecodeCount;
    @XmlElement(name = "RunLengthDecode_Count")
    protected PDFKeywordCountType runLengthDecodeCount;
    @XmlElement(name = "JBIG2Decode_Count")
    protected PDFKeywordCountType jbig2DecodeCount;
    @XmlElement(name = "DCTDecode_Count")
    protected PDFKeywordCountType dctDecodeCount;
    @XmlElement(name = "RichMedia_Count")
    protected PDFKeywordCountType richMediaCount;
    @XmlElement(name = "CCITTFaxDecode_Count")
    protected PDFKeywordCountType ccittFaxDecodeCount;
    @XmlElement(name = "Launch_Count")
    protected PDFKeywordCountType launchCount;
    @XmlElement(name = "XFA_Count")
    protected PDFKeywordCountType xfaCount;

    /**
     * Gets the value of the pageCount property.
     * 
     * @return
     *     possible object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public PDFKeywordCountType getPageCount() {
        return pageCount;
    }

    /**
     * Sets the value of the pageCount property.
     * 
     * @param value
     *     allowed object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public void setPageCount(PDFKeywordCountType value) {
        this.pageCount = value;
    }

    /**
     * Gets the value of the encryptCount property.
     * 
     * @return
     *     possible object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public PDFKeywordCountType getEncryptCount() {
        return encryptCount;
    }

    /**
     * Sets the value of the encryptCount property.
     * 
     * @param value
     *     allowed object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public void setEncryptCount(PDFKeywordCountType value) {
        this.encryptCount = value;
    }

    /**
     * Gets the value of the objStmCount property.
     * 
     * @return
     *     possible object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public PDFKeywordCountType getObjStmCount() {
        return objStmCount;
    }

    /**
     * Sets the value of the objStmCount property.
     * 
     * @param value
     *     allowed object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public void setObjStmCount(PDFKeywordCountType value) {
        this.objStmCount = value;
    }

    /**
     * Gets the value of the jsCount property.
     * 
     * @return
     *     possible object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public PDFKeywordCountType getJSCount() {
        return jsCount;
    }

    /**
     * Sets the value of the jsCount property.
     * 
     * @param value
     *     allowed object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public void setJSCount(PDFKeywordCountType value) {
        this.jsCount = value;
    }

    /**
     * Gets the value of the javaScriptCount property.
     * 
     * @return
     *     possible object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public PDFKeywordCountType getJavaScriptCount() {
        return javaScriptCount;
    }

    /**
     * Sets the value of the javaScriptCount property.
     * 
     * @param value
     *     allowed object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public void setJavaScriptCount(PDFKeywordCountType value) {
        this.javaScriptCount = value;
    }

    /**
     * Gets the value of the aaCount property.
     * 
     * @return
     *     possible object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public PDFKeywordCountType getAACount() {
        return aaCount;
    }

    /**
     * Sets the value of the aaCount property.
     * 
     * @param value
     *     allowed object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public void setAACount(PDFKeywordCountType value) {
        this.aaCount = value;
    }

    /**
     * Gets the value of the openActionCount property.
     * 
     * @return
     *     possible object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public PDFKeywordCountType getOpenActionCount() {
        return openActionCount;
    }

    /**
     * Sets the value of the openActionCount property.
     * 
     * @param value
     *     allowed object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public void setOpenActionCount(PDFKeywordCountType value) {
        this.openActionCount = value;
    }

    /**
     * Gets the value of the asciiHexDecodeCount property.
     * 
     * @return
     *     possible object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public PDFKeywordCountType getASCIIHexDecodeCount() {
        return asciiHexDecodeCount;
    }

    /**
     * Sets the value of the asciiHexDecodeCount property.
     * 
     * @param value
     *     allowed object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public void setASCIIHexDecodeCount(PDFKeywordCountType value) {
        this.asciiHexDecodeCount = value;
    }

    /**
     * Gets the value of the ascii85DecodeCount property.
     * 
     * @return
     *     possible object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public PDFKeywordCountType getASCII85DecodeCount() {
        return ascii85DecodeCount;
    }

    /**
     * Sets the value of the ascii85DecodeCount property.
     * 
     * @param value
     *     allowed object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public void setASCII85DecodeCount(PDFKeywordCountType value) {
        this.ascii85DecodeCount = value;
    }

    /**
     * Gets the value of the lzwDecodeCount property.
     * 
     * @return
     *     possible object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public PDFKeywordCountType getLZWDecodeCount() {
        return lzwDecodeCount;
    }

    /**
     * Sets the value of the lzwDecodeCount property.
     * 
     * @param value
     *     allowed object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public void setLZWDecodeCount(PDFKeywordCountType value) {
        this.lzwDecodeCount = value;
    }

    /**
     * Gets the value of the flateDecodeCount property.
     * 
     * @return
     *     possible object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public PDFKeywordCountType getFlateDecodeCount() {
        return flateDecodeCount;
    }

    /**
     * Sets the value of the flateDecodeCount property.
     * 
     * @param value
     *     allowed object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public void setFlateDecodeCount(PDFKeywordCountType value) {
        this.flateDecodeCount = value;
    }

    /**
     * Gets the value of the runLengthDecodeCount property.
     * 
     * @return
     *     possible object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public PDFKeywordCountType getRunLengthDecodeCount() {
        return runLengthDecodeCount;
    }

    /**
     * Sets the value of the runLengthDecodeCount property.
     * 
     * @param value
     *     allowed object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public void setRunLengthDecodeCount(PDFKeywordCountType value) {
        this.runLengthDecodeCount = value;
    }

    /**
     * Gets the value of the jbig2DecodeCount property.
     * 
     * @return
     *     possible object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public PDFKeywordCountType getJBIG2DecodeCount() {
        return jbig2DecodeCount;
    }

    /**
     * Sets the value of the jbig2DecodeCount property.
     * 
     * @param value
     *     allowed object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public void setJBIG2DecodeCount(PDFKeywordCountType value) {
        this.jbig2DecodeCount = value;
    }

    /**
     * Gets the value of the dctDecodeCount property.
     * 
     * @return
     *     possible object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public PDFKeywordCountType getDCTDecodeCount() {
        return dctDecodeCount;
    }

    /**
     * Sets the value of the dctDecodeCount property.
     * 
     * @param value
     *     allowed object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public void setDCTDecodeCount(PDFKeywordCountType value) {
        this.dctDecodeCount = value;
    }

    /**
     * Gets the value of the richMediaCount property.
     * 
     * @return
     *     possible object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public PDFKeywordCountType getRichMediaCount() {
        return richMediaCount;
    }

    /**
     * Sets the value of the richMediaCount property.
     * 
     * @param value
     *     allowed object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public void setRichMediaCount(PDFKeywordCountType value) {
        this.richMediaCount = value;
    }

    /**
     * Gets the value of the ccittFaxDecodeCount property.
     * 
     * @return
     *     possible object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public PDFKeywordCountType getCCITTFaxDecodeCount() {
        return ccittFaxDecodeCount;
    }

    /**
     * Sets the value of the ccittFaxDecodeCount property.
     * 
     * @param value
     *     allowed object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public void setCCITTFaxDecodeCount(PDFKeywordCountType value) {
        this.ccittFaxDecodeCount = value;
    }

    /**
     * Gets the value of the launchCount property.
     * 
     * @return
     *     possible object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public PDFKeywordCountType getLaunchCount() {
        return launchCount;
    }

    /**
     * Sets the value of the launchCount property.
     * 
     * @param value
     *     allowed object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public void setLaunchCount(PDFKeywordCountType value) {
        this.launchCount = value;
    }

    /**
     * Gets the value of the xfaCount property.
     * 
     * @return
     *     possible object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public PDFKeywordCountType getXFACount() {
        return xfaCount;
    }

    /**
     * Sets the value of the xfaCount property.
     * 
     * @param value
     *     allowed object is
     *     {@link PDFKeywordCountType }
     *     
     */
    public void setXFACount(PDFKeywordCountType value) {
        this.xfaCount = value;
    }

}
