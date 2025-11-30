package ee.taltech.securefiles.db;

import ee.taltech.securefiles.model.FileRecord;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface FileRecordRepository extends JpaRepository<FileRecord, Long> {

    Optional<FileRecord> findByOwnerIdAndOriginalName(Long ownerId, String originalName);
    List<FileRecord> findAllByOwnerId(Long ownerId);
}
