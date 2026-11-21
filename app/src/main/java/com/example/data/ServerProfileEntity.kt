package com.example.data

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "server_profiles")
data class ServerProfileEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0L,
    val name: String,
    val workerUrl: String,
    val uuid: String,
    val cleanIp: String = "",
    val lastLatencyMs: Int? = null,
    val isSelected: Boolean = false,
    val updatedAt: Long = System.currentTimeMillis()
)
