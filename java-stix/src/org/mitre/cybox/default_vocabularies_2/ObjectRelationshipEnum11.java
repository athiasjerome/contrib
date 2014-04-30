//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.04.17 at 04:06:30 PM EDT 
//


package org.mitre.cybox.default_vocabularies_2;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for ObjectRelationshipEnum-1.1.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="ObjectRelationshipEnum-1.1">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="Created"/>
 *     &lt;enumeration value="Created_By"/>
 *     &lt;enumeration value="Deleted"/>
 *     &lt;enumeration value="Deleted_By"/>
 *     &lt;enumeration value="Modified_Properties_Of"/>
 *     &lt;enumeration value="Properties_Modified_By"/>
 *     &lt;enumeration value="Read_From"/>
 *     &lt;enumeration value="Read_From_By"/>
 *     &lt;enumeration value="Wrote_To"/>
 *     &lt;enumeration value="Written_To_By"/>
 *     &lt;enumeration value="Downloaded_From"/>
 *     &lt;enumeration value="Downloaded_To"/>
 *     &lt;enumeration value="Downloaded"/>
 *     &lt;enumeration value="Downloaded_By"/>
 *     &lt;enumeration value="Uploaded"/>
 *     &lt;enumeration value="Uploaded_By"/>
 *     &lt;enumeration value="Uploaded_To"/>
 *     &lt;enumeration value="Received_Via_Upload"/>
 *     &lt;enumeration value="Uploaded_From"/>
 *     &lt;enumeration value="Sent_Via_Upload"/>
 *     &lt;enumeration value="Suspended"/>
 *     &lt;enumeration value="Suspended_By"/>
 *     &lt;enumeration value="Paused"/>
 *     &lt;enumeration value="Paused_By"/>
 *     &lt;enumeration value="Resumed"/>
 *     &lt;enumeration value="Resumed_By"/>
 *     &lt;enumeration value="Opened"/>
 *     &lt;enumeration value="Opened_By"/>
 *     &lt;enumeration value="Closed"/>
 *     &lt;enumeration value="Closed_By"/>
 *     &lt;enumeration value="Copied_From"/>
 *     &lt;enumeration value="Copied_To"/>
 *     &lt;enumeration value="Copied"/>
 *     &lt;enumeration value="Copied_By"/>
 *     &lt;enumeration value="Moved_From"/>
 *     &lt;enumeration value="Moved_To"/>
 *     &lt;enumeration value="Moved"/>
 *     &lt;enumeration value="Moved_By"/>
 *     &lt;enumeration value="Searched_For"/>
 *     &lt;enumeration value="Searched_For_By"/>
 *     &lt;enumeration value="Allocated"/>
 *     &lt;enumeration value="Allocated_By"/>
 *     &lt;enumeration value="Initialized_To"/>
 *     &lt;enumeration value="Initialized_By"/>
 *     &lt;enumeration value="Sent"/>
 *     &lt;enumeration value="Sent_By"/>
 *     &lt;enumeration value="Sent_To"/>
 *     &lt;enumeration value="Received_From"/>
 *     &lt;enumeration value="Received"/>
 *     &lt;enumeration value="Received_By"/>
 *     &lt;enumeration value="Mapped_Into"/>
 *     &lt;enumeration value="Mapped_By"/>
 *     &lt;enumeration value="Properties_Queried"/>
 *     &lt;enumeration value="Properties_Queried_By"/>
 *     &lt;enumeration value="Values_Enumerated"/>
 *     &lt;enumeration value="Values_Enumerated_By"/>
 *     &lt;enumeration value="Bound"/>
 *     &lt;enumeration value="Bound_By"/>
 *     &lt;enumeration value="Freed"/>
 *     &lt;enumeration value="Freed_By"/>
 *     &lt;enumeration value="Killed"/>
 *     &lt;enumeration value="Killed_By"/>
 *     &lt;enumeration value="Encrypted"/>
 *     &lt;enumeration value="Encrypted_By"/>
 *     &lt;enumeration value="Encrypted_To"/>
 *     &lt;enumeration value="Encrypted_From"/>
 *     &lt;enumeration value="Decrypted"/>
 *     &lt;enumeration value="Decrypted_By"/>
 *     &lt;enumeration value="Packed"/>
 *     &lt;enumeration value="Packed_By"/>
 *     &lt;enumeration value="Unpacked"/>
 *     &lt;enumeration value="Unpacked_By"/>
 *     &lt;enumeration value="Packed_From"/>
 *     &lt;enumeration value="Packed_Into"/>
 *     &lt;enumeration value="Encoded"/>
 *     &lt;enumeration value="Encoded_By"/>
 *     &lt;enumeration value="Decoded"/>
 *     &lt;enumeration value="Decoded_By"/>
 *     &lt;enumeration value="Compressed_From"/>
 *     &lt;enumeration value="Compressed_Into"/>
 *     &lt;enumeration value="Compressed"/>
 *     &lt;enumeration value="Compressed_By"/>
 *     &lt;enumeration value="Decompressed"/>
 *     &lt;enumeration value="Decompressed_By"/>
 *     &lt;enumeration value="Joined"/>
 *     &lt;enumeration value="Joined_By"/>
 *     &lt;enumeration value="Merged"/>
 *     &lt;enumeration value="Merged_By"/>
 *     &lt;enumeration value="Locked"/>
 *     &lt;enumeration value="Locked_By"/>
 *     &lt;enumeration value="Unlocked"/>
 *     &lt;enumeration value="Unlocked_By"/>
 *     &lt;enumeration value="Hooked"/>
 *     &lt;enumeration value="Hooked_By"/>
 *     &lt;enumeration value="Unhooked"/>
 *     &lt;enumeration value="Unhooked_By"/>
 *     &lt;enumeration value="Monitored"/>
 *     &lt;enumeration value="Monitored_By"/>
 *     &lt;enumeration value="Listened_On"/>
 *     &lt;enumeration value="Listened_On_By"/>
 *     &lt;enumeration value="Renamed_From"/>
 *     &lt;enumeration value="Renamed_To"/>
 *     &lt;enumeration value="Renamed"/>
 *     &lt;enumeration value="Renamed_By"/>
 *     &lt;enumeration value="Injected_Into"/>
 *     &lt;enumeration value="Injected_As"/>
 *     &lt;enumeration value="Injected"/>
 *     &lt;enumeration value="Injected_By"/>
 *     &lt;enumeration value="Deleted_From"/>
 *     &lt;enumeration value="Previously_Contained"/>
 *     &lt;enumeration value="Loaded_Into"/>
 *     &lt;enumeration value="Loaded_From"/>
 *     &lt;enumeration value="Set_To"/>
 *     &lt;enumeration value="Set_From"/>
 *     &lt;enumeration value="Resolved_To"/>
 *     &lt;enumeration value="Related_To"/>
 *     &lt;enumeration value="Dropped"/>
 *     &lt;enumeration value="Dropped_By"/>
 *     &lt;enumeration value="Contains"/>
 *     &lt;enumeration value="Contained_Within"/>
 *     &lt;enumeration value="Extracted_From"/>
 *     &lt;enumeration value="Installed"/>
 *     &lt;enumeration value="Installed_By"/>
 *     &lt;enumeration value="Connected_To"/>
 *     &lt;enumeration value="Connected_From"/>
 *     &lt;enumeration value="Sub-domain_Of"/>
 *     &lt;enumeration value="Supra-domain_Of"/>
 *     &lt;enumeration value="Root_Domain_Of"/>
 *     &lt;enumeration value="FQDN_Of"/>
 *     &lt;enumeration value="Parent_Of"/>
 *     &lt;enumeration value="Child_Of"/>
 *     &lt;enumeration value="Characterizes"/>
 *     &lt;enumeration value="Characterized_By"/>
 *     &lt;enumeration value="Used"/>
 *     &lt;enumeration value="Used_By"/>
 *     &lt;enumeration value="Redirects_To"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "ObjectRelationshipEnum-1.1")
@XmlEnum
public enum ObjectRelationshipEnum11 {


    /**
     * Specifies that this object created the related object.
     * 
     */
    @XmlEnumValue("Created")
    CREATED("Created"),

    /**
     * Specifies that this object was created by the related object.
     * 
     */
    @XmlEnumValue("Created_By")
    CREATED_BY("Created_By"),

    /**
     * Specifies that this object deleted the related object.
     * 
     */
    @XmlEnumValue("Deleted")
    DELETED("Deleted"),

    /**
     * Specifies that this object was deleted by the related object.
     * 
     */
    @XmlEnumValue("Deleted_By")
    DELETED_BY("Deleted_By"),

    /**
     * Specifies that this object modified the properties of the related object.
     * 
     */
    @XmlEnumValue("Modified_Properties_Of")
    MODIFIED_PROPERTIES_OF("Modified_Properties_Of"),

    /**
     * Specifies that the properties of this object were modified by the related object.
     * 
     */
    @XmlEnumValue("Properties_Modified_By")
    PROPERTIES_MODIFIED_BY("Properties_Modified_By"),

    /**
     * Specifies that this object was read from the related object.
     * 
     */
    @XmlEnumValue("Read_From")
    READ_FROM("Read_From"),

    /**
     * Specifies that this object was read from by the related object.
     * 
     */
    @XmlEnumValue("Read_From_By")
    READ_FROM_BY("Read_From_By"),

    /**
     * Specifies that this object wrote to the related object.
     * 
     */
    @XmlEnumValue("Wrote_To")
    WROTE_TO("Wrote_To"),

    /**
     * Specifies that this object was written to by the related object.
     * 
     */
    @XmlEnumValue("Written_To_By")
    WRITTEN_TO_BY("Written_To_By"),

    /**
     * Specifies that this object was downloaded from the related object.
     * 
     */
    @XmlEnumValue("Downloaded_From")
    DOWNLOADED_FROM("Downloaded_From"),

    /**
     * Specifies that this object downloaded the related object.
     * 
     */
    @XmlEnumValue("Downloaded_To")
    DOWNLOADED_TO("Downloaded_To"),

    /**
     * Specifies that this object downloaded the related object.
     * 
     */
    @XmlEnumValue("Downloaded")
    DOWNLOADED("Downloaded"),

    /**
     * Specifies that this object was downloaded by the related object.
     * 
     */
    @XmlEnumValue("Downloaded_By")
    DOWNLOADED_BY("Downloaded_By"),

    /**
     * Specifies that this object uploaded the related object.
     * 
     */
    @XmlEnumValue("Uploaded")
    UPLOADED("Uploaded"),

    /**
     * Specifies that this object was uploaded by the related object.
     * 
     */
    @XmlEnumValue("Uploaded_By")
    UPLOADED_BY("Uploaded_By"),

    /**
     * Specifies that this object was uploaded to the related object.
     * 
     */
    @XmlEnumValue("Uploaded_To")
    UPLOADED_TO("Uploaded_To"),

    /**
     * Specifies that this object received the related object via upload.
     * 
     */
    @XmlEnumValue("Received_Via_Upload")
    RECEIVED_VIA_UPLOAD("Received_Via_Upload"),

    /**
     * Specifies that this object was uploaded from the related object.
     * 
     */
    @XmlEnumValue("Uploaded_From")
    UPLOADED_FROM("Uploaded_From"),

    /**
     * Specifies that this object sent the related object via upload.
     * 
     */
    @XmlEnumValue("Sent_Via_Upload")
    SENT_VIA_UPLOAD("Sent_Via_Upload"),

    /**
     * Specifies that this object suspended the related object.
     * 
     */
    @XmlEnumValue("Suspended")
    SUSPENDED("Suspended"),

    /**
     * Specifies that this object was suspended by the related object.
     * 
     */
    @XmlEnumValue("Suspended_By")
    SUSPENDED_BY("Suspended_By"),

    /**
     * Specifies that this object paused the related object.
     * 
     */
    @XmlEnumValue("Paused")
    PAUSED("Paused"),

    /**
     * Specifies that this object was paused by the related object.
     * 
     */
    @XmlEnumValue("Paused_By")
    PAUSED_BY("Paused_By"),

    /**
     * Specifies that this object resumed the related object.
     * 
     */
    @XmlEnumValue("Resumed")
    RESUMED("Resumed"),

    /**
     * Specifies that this object was resumed by the related object.
     * 
     */
    @XmlEnumValue("Resumed_By")
    RESUMED_BY("Resumed_By"),

    /**
     * Specifies that this object opened the related object.
     * 
     */
    @XmlEnumValue("Opened")
    OPENED("Opened"),

    /**
     * Specifies that this object was opened by the related object.
     * 
     */
    @XmlEnumValue("Opened_By")
    OPENED_BY("Opened_By"),

    /**
     * Specifies that this object closed the related object.
     * 
     */
    @XmlEnumValue("Closed")
    CLOSED("Closed"),

    /**
     * Specifies that this object was closed by the related object.
     * 
     */
    @XmlEnumValue("Closed_By")
    CLOSED_BY("Closed_By"),

    /**
     * Specifies that this object was copied from the related object.
     * 
     */
    @XmlEnumValue("Copied_From")
    COPIED_FROM("Copied_From"),

    /**
     * Specifies that this object was copied to the related object.
     * 
     */
    @XmlEnumValue("Copied_To")
    COPIED_TO("Copied_To"),

    /**
     * Specifies that this object copied the related object.
     * 
     */
    @XmlEnumValue("Copied")
    COPIED("Copied"),

    /**
     * Specifies that this object was copied by the related object.
     * 
     */
    @XmlEnumValue("Copied_By")
    COPIED_BY("Copied_By"),

    /**
     * Specifies that this object was moved from the related object.
     * 
     */
    @XmlEnumValue("Moved_From")
    MOVED_FROM("Moved_From"),

    /**
     * Specifies that this object was moved to the related object.
     * 
     */
    @XmlEnumValue("Moved_To")
    MOVED_TO("Moved_To"),

    /**
     * Specifies that this object moved the related object.
     * 
     */
    @XmlEnumValue("Moved")
    MOVED("Moved"),

    /**
     * Specifies that this object was moved by the related object.
     * 
     */
    @XmlEnumValue("Moved_By")
    MOVED_BY("Moved_By"),

    /**
     * Specifies that this object searched for the related object.
     * 
     */
    @XmlEnumValue("Searched_For")
    SEARCHED_FOR("Searched_For"),

    /**
     * Specifies that this object was searched for by the related object.
     * 
     */
    @XmlEnumValue("Searched_For_By")
    SEARCHED_FOR_BY("Searched_For_By"),

    /**
     * Specifies that this object allocated the related object.
     * 
     */
    @XmlEnumValue("Allocated")
    ALLOCATED("Allocated"),

    /**
     * Specifies that this object was allocated by the related object.
     * 
     */
    @XmlEnumValue("Allocated_By")
    ALLOCATED_BY("Allocated_By"),

    /**
     * Specifies that this object was initialized to the related object.
     * 
     */
    @XmlEnumValue("Initialized_To")
    INITIALIZED_TO("Initialized_To"),

    /**
     * Specifies that this object was initialized by the related object.
     * 
     */
    @XmlEnumValue("Initialized_By")
    INITIALIZED_BY("Initialized_By"),

    /**
     * Specifies that this object sent the related object.
     * 
     */
    @XmlEnumValue("Sent")
    SENT("Sent"),

    /**
     * Specifies that this object was sent by the related object.
     * 
     */
    @XmlEnumValue("Sent_By")
    SENT_BY("Sent_By"),

    /**
     * Specifies that this object was sent to the related object.
     * 
     */
    @XmlEnumValue("Sent_To")
    SENT_TO("Sent_To"),

    /**
     * Specifies that this object was received from the related object.
     * 
     */
    @XmlEnumValue("Received_From")
    RECEIVED_FROM("Received_From"),

    /**
     * Specifies that this object received the related object.
     * 
     */
    @XmlEnumValue("Received")
    RECEIVED("Received"),

    /**
     * Specifies that this object was received by the related object.
     * 
     */
    @XmlEnumValue("Received_By")
    RECEIVED_BY("Received_By"),

    /**
     * Specifies that this object was mapped into the related object.
     * 
     */
    @XmlEnumValue("Mapped_Into")
    MAPPED_INTO("Mapped_Into"),

    /**
     * Specifies that this object was mapped by the related object.
     * 
     */
    @XmlEnumValue("Mapped_By")
    MAPPED_BY("Mapped_By"),

    /**
     * Specifies that the object queried properties of the related object.
     * 
     */
    @XmlEnumValue("Properties_Queried")
    PROPERTIES_QUERIED("Properties_Queried"),

    /**
     * Specifies that the properties of this object were queried by the related object.
     * 
     */
    @XmlEnumValue("Properties_Queried_By")
    PROPERTIES_QUERIED_BY("Properties_Queried_By"),

    /**
     * Specifies that the object enumerated values of the related object.
     * 
     */
    @XmlEnumValue("Values_Enumerated")
    VALUES_ENUMERATED("Values_Enumerated"),

    /**
     * Specifies that the values of the object were enumerated by the related object.
     * 
     */
    @XmlEnumValue("Values_Enumerated_By")
    VALUES_ENUMERATED_BY("Values_Enumerated_By"),

    /**
     * Specifies that this object bound the related object.
     * 
     */
    @XmlEnumValue("Bound")
    BOUND("Bound"),

    /**
     * Specifies that this object was bound by the related object.
     * 
     */
    @XmlEnumValue("Bound_By")
    BOUND_BY("Bound_By"),

    /**
     * Specifies that this object freed the related object.
     * 
     */
    @XmlEnumValue("Freed")
    FREED("Freed"),

    /**
     * Specifies that this object was freed by the related object.
     * 
     */
    @XmlEnumValue("Freed_By")
    FREED_BY("Freed_By"),

    /**
     * Specifies that this object killed the related object.
     * 
     */
    @XmlEnumValue("Killed")
    KILLED("Killed"),

    /**
     * Specifies that this object was killed by the related object.
     * 
     */
    @XmlEnumValue("Killed_By")
    KILLED_BY("Killed_By"),

    /**
     * Specifies that this object encrypted the related object.
     * 
     */
    @XmlEnumValue("Encrypted")
    ENCRYPTED("Encrypted"),

    /**
     * Specifies that this object was encrypted by the related object.
     * 
     */
    @XmlEnumValue("Encrypted_By")
    ENCRYPTED_BY("Encrypted_By"),

    /**
     * Specifies that this object was encrypted to the related object.
     * 
     */
    @XmlEnumValue("Encrypted_To")
    ENCRYPTED_TO("Encrypted_To"),

    /**
     * Specifies that this object was encrypted from the related object.
     * 
     */
    @XmlEnumValue("Encrypted_From")
    ENCRYPTED_FROM("Encrypted_From"),

    /**
     * Specifies that this object decrypted the related object.
     * 
     */
    @XmlEnumValue("Decrypted")
    DECRYPTED("Decrypted"),

    /**
     * Specifies that this object was decrypted by the related object.
     * 
     */
    @XmlEnumValue("Decrypted_By")
    DECRYPTED_BY("Decrypted_By"),

    /**
     * Specifies that this object packed the related object.
     * 
     */
    @XmlEnumValue("Packed")
    PACKED("Packed"),

    /**
     * Specifies that this object was packed by the related object.
     * 
     */
    @XmlEnumValue("Packed_By")
    PACKED_BY("Packed_By"),

    /**
     * Specifies that this object unpacked the related object.
     * 
     */
    @XmlEnumValue("Unpacked")
    UNPACKED("Unpacked"),

    /**
     * Specifies that this object was unpacked by the related object.
     * 
     */
    @XmlEnumValue("Unpacked_By")
    UNPACKED_BY("Unpacked_By"),

    /**
     * Specifies that this object was packed from the related object.
     * 
     */
    @XmlEnumValue("Packed_From")
    PACKED_FROM("Packed_From"),

    /**
     * Specifies that this object was packed into the related object.
     * 
     */
    @XmlEnumValue("Packed_Into")
    PACKED_INTO("Packed_Into"),

    /**
     * Specifies that this object encoded the related object.
     * 
     */
    @XmlEnumValue("Encoded")
    ENCODED("Encoded"),

    /**
     * Specifies that this object was encoded by the related object.
     * 
     */
    @XmlEnumValue("Encoded_By")
    ENCODED_BY("Encoded_By"),

    /**
     * Specifies that this object decoded the related object.
     * 
     */
    @XmlEnumValue("Decoded")
    DECODED("Decoded"),

    /**
     * Specifies that this object was decoded by the related object.
     * 
     */
    @XmlEnumValue("Decoded_By")
    DECODED_BY("Decoded_By"),

    /**
     * Specifies that this object was compressed from the related object.
     * 
     */
    @XmlEnumValue("Compressed_From")
    COMPRESSED_FROM("Compressed_From"),

    /**
     * Specifies that this object was compressed into the related object.
     * 
     */
    @XmlEnumValue("Compressed_Into")
    COMPRESSED_INTO("Compressed_Into"),

    /**
     * Specifies that this object compressed the related object.
     * 
     */
    @XmlEnumValue("Compressed")
    COMPRESSED("Compressed"),

    /**
     * Specifies that this object was compressed by the related object.
     * 
     */
    @XmlEnumValue("Compressed_By")
    COMPRESSED_BY("Compressed_By"),

    /**
     * Specifies that this object decompressed the related object.
     * 
     */
    @XmlEnumValue("Decompressed")
    DECOMPRESSED("Decompressed"),

    /**
     * Specifies that this object was decompressed by the related object.
     * 
     */
    @XmlEnumValue("Decompressed_By")
    DECOMPRESSED_BY("Decompressed_By"),

    /**
     * Specifies that this object joined the related object.
     * 
     */
    @XmlEnumValue("Joined")
    JOINED("Joined"),

    /**
     * Specifies that this object was joined by the related object.
     * 
     */
    @XmlEnumValue("Joined_By")
    JOINED_BY("Joined_By"),

    /**
     * Specifies that this object merged the related object.
     * 
     */
    @XmlEnumValue("Merged")
    MERGED("Merged"),

    /**
     * Specifies that this object was merged by the related object.
     * 
     */
    @XmlEnumValue("Merged_By")
    MERGED_BY("Merged_By"),

    /**
     * Specifies that this object locked the related object.
     * 
     */
    @XmlEnumValue("Locked")
    LOCKED("Locked"),

    /**
     * Specifies that this object was locked by the related object.
     * 
     */
    @XmlEnumValue("Locked_By")
    LOCKED_BY("Locked_By"),

    /**
     * Specifies that this object unlocked the related object.
     * 
     */
    @XmlEnumValue("Unlocked")
    UNLOCKED("Unlocked"),

    /**
     * Specifies that this object was unlocked by the related object.
     * 
     */
    @XmlEnumValue("Unlocked_By")
    UNLOCKED_BY("Unlocked_By"),

    /**
     * Specifies that this object hooked the related object.
     * 
     */
    @XmlEnumValue("Hooked")
    HOOKED("Hooked"),

    /**
     * Specifies that this object was hooked by the related object.
     * 
     */
    @XmlEnumValue("Hooked_By")
    HOOKED_BY("Hooked_By"),

    /**
     * Specifies that this object unhooked the related object.
     * 
     */
    @XmlEnumValue("Unhooked")
    UNHOOKED("Unhooked"),

    /**
     * Specifies that this object was unhooked by the related object.
     * 
     */
    @XmlEnumValue("Unhooked_By")
    UNHOOKED_BY("Unhooked_By"),

    /**
     * Specifies that this object monitored the related object.
     * 
     */
    @XmlEnumValue("Monitored")
    MONITORED("Monitored"),

    /**
     * Specifies that this object was monitored by the related object.
     * 
     */
    @XmlEnumValue("Monitored_By")
    MONITORED_BY("Monitored_By"),

    /**
     * Specifies that this object listened on the related object.
     * 
     */
    @XmlEnumValue("Listened_On")
    LISTENED_ON("Listened_On"),

    /**
     * Specifies that this object was listened on by the related object.
     * 
     */
    @XmlEnumValue("Listened_On_By")
    LISTENED_ON_BY("Listened_On_By"),

    /**
     * Specifies that this object was renamed from the related object.
     * 
     */
    @XmlEnumValue("Renamed_From")
    RENAMED_FROM("Renamed_From"),

    /**
     * Specifies that this object was renamed to the related object.
     * 
     */
    @XmlEnumValue("Renamed_To")
    RENAMED_TO("Renamed_To"),

    /**
     * Specifies that this object renamed the related object.
     * 
     */
    @XmlEnumValue("Renamed")
    RENAMED("Renamed"),

    /**
     * Specifies that this object was renamed by the related object.
     * 
     */
    @XmlEnumValue("Renamed_By")
    RENAMED_BY("Renamed_By"),

    /**
     * Specifies that this object injected into the related object.
     * 
     */
    @XmlEnumValue("Injected_Into")
    INJECTED_INTO("Injected_Into"),

    /**
     * Specifies that this object injected as the related object.
     * 
     */
    @XmlEnumValue("Injected_As")
    INJECTED_AS("Injected_As"),

    /**
     * Specifies that this object injected the related object.
     * 
     */
    @XmlEnumValue("Injected")
    INJECTED("Injected"),

    /**
     * Specifies that this object was injected by the related object.
     * 
     */
    @XmlEnumValue("Injected_By")
    INJECTED_BY("Injected_By"),

    /**
     * Specifies that this object was deleted from the related object.
     * 
     */
    @XmlEnumValue("Deleted_From")
    DELETED_FROM("Deleted_From"),

    /**
     * Specifies that this object previously contained the related object.
     * 
     */
    @XmlEnumValue("Previously_Contained")
    PREVIOUSLY_CONTAINED("Previously_Contained"),

    /**
     * Specifies that this object loaded into the related object.
     * 
     */
    @XmlEnumValue("Loaded_Into")
    LOADED_INTO("Loaded_Into"),

    /**
     * Specifies that this object was loaded from the related object.
     * 
     */
    @XmlEnumValue("Loaded_From")
    LOADED_FROM("Loaded_From"),

    /**
     * Specifies that this object was set to the related object.
     * 
     */
    @XmlEnumValue("Set_To")
    SET_TO("Set_To"),

    /**
     * Specifies that this object was set from the related object.
     * 
     */
    @XmlEnumValue("Set_From")
    SET_FROM("Set_From"),

    /**
     * Specifies that this object was resolved to the related object.
     * 
     */
    @XmlEnumValue("Resolved_To")
    RESOLVED_TO("Resolved_To"),

    /**
     * Specifies that this object is related to the related object.
     * 
     */
    @XmlEnumValue("Related_To")
    RELATED_TO("Related_To"),

    /**
     * Specifies that this object dropped the related object.
     * 
     */
    @XmlEnumValue("Dropped")
    DROPPED("Dropped"),

    /**
     * Specifies that this object was dropped by the related object.
     * 
     */
    @XmlEnumValue("Dropped_By")
    DROPPED_BY("Dropped_By"),

    /**
     * Specifies that this object contains the related object.
     * 
     */
    @XmlEnumValue("Contains")
    CONTAINS("Contains"),

    /**
     * Specifies that this object is contained within the related object.
     * 
     */
    @XmlEnumValue("Contained_Within")
    CONTAINED_WITHIN("Contained_Within"),

    /**
     * Specifies that this object was extracted from the related object.
     * 
     */
    @XmlEnumValue("Extracted_From")
    EXTRACTED_FROM("Extracted_From"),

    /**
     * Specifies that this object installed the related object.
     * 
     */
    @XmlEnumValue("Installed")
    INSTALLED("Installed"),

    /**
     * Specifies that this object was installed by the related object.
     * 
     */
    @XmlEnumValue("Installed_By")
    INSTALLED_BY("Installed_By"),

    /**
     * Specifies that this object connected to the related object.
     * 
     */
    @XmlEnumValue("Connected_To")
    CONNECTED_TO("Connected_To"),

    /**
     * Specifies that this object was connected to from the related object.
     * 
     */
    @XmlEnumValue("Connected_From")
    CONNECTED_FROM("Connected_From"),

    /**
     * Specifies that this object is a sub-domain of the related object.
     * 
     */
    @XmlEnumValue("Sub-domain_Of")
    SUB_DOMAIN_OF("Sub-domain_Of"),

    /**
     * Specifies that this object is a supra-domain of the related object.
     * 
     */
    @XmlEnumValue("Supra-domain_Of")
    SUPRA_DOMAIN_OF("Supra-domain_Of"),

    /**
     * Specifies that this object is the root domain of the related object.
     * 
     */
    @XmlEnumValue("Root_Domain_Of")
    ROOT_DOMAIN_OF("Root_Domain_Of"),

    /**
     * Specifies that this object is an FQDN of the related object.
     * 
     */
    @XmlEnumValue("FQDN_Of")
    FQDN_OF("FQDN_Of"),

    /**
     * Specifies that this object is a parent of the related object.
     * 
     */
    @XmlEnumValue("Parent_Of")
    PARENT_OF("Parent_Of"),

    /**
     * Specifies that this object is a child of the related object.
     * 
     */
    @XmlEnumValue("Child_Of")
    CHILD_OF("Child_Of"),

    /**
     * Specifies that this object describes the properties of the related object. This is most applicable in cases where the related object is an Artifact Object and this object is a non-Artifact Object.
     * 
     */
    @XmlEnumValue("Characterizes")
    CHARACTERIZES("Characterizes"),

    /**
     * Specifies that the related object describes the properties of this object. This is most applicable in cases where the related object is a non-Artifact Object and this object is an Artifact Object.
     * 
     */
    @XmlEnumValue("Characterized_By")
    CHARACTERIZED_BY("Characterized_By"),

    /**
     * Specifies that this object used the related object.
     * 
     */
    @XmlEnumValue("Used")
    USED("Used"),

    /**
     * Specifies that this object was used by the related object.
     * 
     */
    @XmlEnumValue("Used_By")
    USED_BY("Used_By"),

    /**
     * Specifies that this object redirects to the related object.
     * 
     */
    @XmlEnumValue("Redirects_To")
    REDIRECTS_TO("Redirects_To");
    private final String value;

    ObjectRelationshipEnum11(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static ObjectRelationshipEnum11 fromValue(String v) {
        for (ObjectRelationshipEnum11 c: ObjectRelationshipEnum11 .values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
