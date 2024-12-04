Let me analyze the core data structures used in this codebase based on the provided source code. I'll explain each one and its purpose.

1. Entry and EntryData
The Entry class represents an individual password entry in the database, with EntryData holding its core attributes:
```cpp
struct EntryData {
    int iconNumber;                  // Icon identifier
    QUuid customIcon;               // Custom icon UUID
    QString foregroundColor;        // Text color
    QString backgroundColor;        // Background color
    QString overrideUrl;           // Override for URL field
    QStringList tags;              // List of tags
    bool autoTypeEnabled;          // Auto-type enabled flag
    int autoTypeObfuscation;       // Auto-type obfuscation level
    QString defaultAutoTypeSequence; // Default auto-type sequence
    TimeInfo timeInfo;             // Timestamps and time-related data
    QSharedPointer<Totp::Settings> totpSettings;  // TOTP settings if enabled
    QSharedPointer<PasswordHealth> passwordHealth; // Password strength metrics
    bool excludeFromReports;       // Exclude from health reports
    QUuid previousParentGroupUuid; // Previous parent group UUID
};
```

2. Group
The Group class represents a folder/group that can contain entries and other groups:
```cpp
struct GroupData {
    QString name;                   // Group name
    QString notes;                 // Group notes/description
    QString tags;                  // Group tags
    int iconNumber;               // Icon identifier
    QUuid customIcon;             // Custom icon UUID
    TimeInfo timeInfo;            // Time-related data
    bool isExpanded;              // UI expanded state
    QString defaultAutoTypeSequence; // Default auto-type sequence
    Group::TriState autoTypeEnabled; // Auto-type state (Enable/Disable/Inherit)
    Group::TriState searchingEnabled; // Search state
    Group::MergeMode mergeMode;    // How to merge with other groups
    QUuid previousParentGroupUuid; // Previous parent group UUID
};
```

3. TimeInfo
TimeInfo tracks various timestamps for entries and groups:
```cpp
class TimeInfo {
    QDateTime m_lastModificationTime; // Last modified timestamp
    QDateTime m_creationTime;        // Creation timestamp
    QDateTime m_lastAccessTime;      // Last accessed timestamp
    QDateTime m_expiryTime;          // Expiration timestamp
    bool m_expires;                  // Whether entry expires
    int m_usageCount;               // Number of times used
    QDateTime m_locationChanged;     // Last location change
};
```

4. CustomData
CustomData allows storing arbitrary key-value pairs:
```cpp
class CustomData {
    QMap<QString, QString> m_attributes;       // Key-value store
    QSet<QString> m_protectedAttributes;      // Protected attributes set
};
```

5. Database
The Database class ties everything together:
```cpp
class Database {
    struct DatabaseData {
        quint32 formatVersion;                // Database format version
        QString filePath;                     // Database file path
        QUuid cipher;                         // Encryption cipher
        CompressionAlgorithm compressionAlgorithm; // Compression type
        QSharedPointer<const CompositeKey> key;    // Master key
        QSharedPointer<Kdf> kdf;                   // Key derivation function
        QVariantMap publicCustomData;              // Public metadata
    };

    Metadata* m_metadata;           // Database metadata
    Group* m_rootGroup;            // Root group containing all entries
    QList<DeletedObject> m_deletedObjects; // Tracks deleted objects
    bool m_modified;               // Modified flag
};
```

These data structures form a tree-like hierarchy:

- Database contains a root Group and Metadata
- Groups can contain other Groups and Entries forming a tree
- Entries contain the actual sensitive data (passwords, notes, etc.)
- TimeInfo, CustomData, and other supporting structures provide additional functionality

The design follows good object-oriented principles with clear separation of concerns, encapsulation of data, and relationships between objects. The extensive use of Qt's data structures (QString, QDateTime, etc.) provides cross-platform compatibility and robust string/data handling.

This architecture allows for efficient organization and management of password entries while maintaining security through encryption and careful handling of sensitive data.
