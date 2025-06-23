# ClickHouse Storage Management - Complete Implementation

## Overview
Fixed inaccurate storage allocation and implemented comprehensive storage management with real filesystem awareness and data retention policies.

## Issues Fixed

### ❌ **Original Problem**
- **Allocated Space**: 200 GB (impossible on 98GB filesystem)
- **Available Space**: Only 27 GB actual 
- **No Validation**: Could set unrealistic allocations
- **No Data Retention**: Data accumulated indefinitely

### ✅ **Solution Implemented**

## 🔧 **Storage Allocation Accuracy**

### **Real Filesystem Integration**
- **Total Filesystem**: 97.9 GB
- **Used by System**: 66.3 GB (67.8%)
- **Available Space**: 26.5 GB
- **Current ClickHouse**: 28.0 GB (uses 140% of current 20GB allocation)

### **Smart Allocation Suggestions**
- **Suggested**: 19 GB (70% of available space)
- **Maximum Possible**: 27 GB (100% of available space)
- **Current Setting**: 20 GB (realistic but already exceeded)

## 🛡️ **Validation & Safety**

### **Frontend Validation**
- **Minimum**: 5 GB
- **Maximum**: Dynamic based on actual available space
- **Real-time Updates**: Shows filesystem info in configuration modal
- **Visual Warnings**: Progress bars change color when approaching limits

### **Backend Validation**
- **Filesystem Checks**: Validates against actual available space
- **Error Messages**: Clear feedback when limits exceeded
- **Automatic Suggestions**: Calculates reasonable allocations

## 📊 **Enhanced UI Features**

### **Storage Summary Display**
```
Actual Disk Usage: 28.0 GB (filesystem measurement)
ClickHouse Reported: 26.5 GB (database tables only)
Allocated Space: 20.0 GB
Status: Critical (140% of allocation used)
```

### **Filesystem Information Panel**
```
Total Filesystem: 97.9 GB
Used by System: 66.3 GB (67.8%)
Available Space: 26.5 GB
Max Allocation: 27 GB
```

### **Configuration Modal Updates**
- **Real-time Filesystem Info**: Shows total/used/available space
- **Dynamic Validation**: Input limits adjust based on available space
- **Smart Defaults**: Suggests 70% of available space
- **Data Retention Settings**: Configure automatic cleanup

## 🔄 **Data Retention & Cleanup**

### **Retention Configuration**
- **Default Retention**: 90 days
- **Range**: 30-365 days
- **Auto Cleanup**: Enabled by default
- **Manual Override**: Can disable auto-cleanup

### **Cleanup Script**
- **Location**: `/home/net/analyzer/scripts/clickhouse_data_cleanup.py`
- **Features**: 
  - Dry-run mode for testing
  - Configurable retention periods
  - Logging of cleanup operations
  - Table-by-table processing

### **Cleanup Capabilities**
```bash
# Test what would be cleaned
python clickhouse_data_cleanup.py --dry-run --retention-days 60

# Actual cleanup with custom retention
python clickhouse_data_cleanup.py --retention-days 60
```

## 📈 **Current Status**

### **Storage Allocation**
- **Configured**: 20.0 GB
- **Actual Usage**: 28.0 GB 
- **Status**: ⚠️ Critical (140% over allocation)
- **Recommendation**: Either increase allocation to 25GB or clean up old data

### **Table Breakdown**
- **fortigate_traffic**: 9.00 GiB (91.7M records)
- **pa_traffic**: 456.76 MiB (3.2M records)
- **threat_logs**: 99.64 MiB (682K records)
- **Other tables**: Additional data

### **Immediate Actions Needed**
1. **Increase Allocation** to 25GB (within available space)
2. **Run Data Cleanup** to remove old data
3. **Setup Automated Cleanup** cron job

## 🚀 **Recommended Next Steps**

### **1. Adjust Allocation (Immediate)**
```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"allocated_space_gb": 25}' \
  http://10.12.50.61:8001/log-management/storage/allocation/
```

### **2. Clean Up Old Data**
```bash
# Test first
python /home/net/analyzer/scripts/clickhouse_data_cleanup.py --dry-run --retention-days 60

# Actually clean up data older than 60 days
python /home/net/analyzer/scripts/clickhouse_data_cleanup.py --retention-days 60
```

### **3. Setup Automated Cleanup**
Add to crontab:
```bash
# Run cleanup daily at 2 AM
0 2 * * * /home/net/analyzer/env/bin/python /home/net/analyzer/scripts/clickhouse_data_cleanup.py
```

### **4. Monitor Growth**
- **Watch Usage**: Monitor the storage dashboard
- **Adjust Retention**: Reduce retention days if growth is too fast
- **Scale Allocation**: Increase allocation if needed (within filesystem limits)

## 📁 **Files Created/Modified**

### **Configuration Files**
- `/home/net/analyzer/config/clickhouse_storage.json` - Storage allocation settings
- `/home/net/analyzer/config/clickhouse_disk_usage.json` - Actual disk usage tracking

### **Scripts**
- `/home/net/analyzer/scripts/clickhouse_data_cleanup.py` - Data retention management
- `/home/net/analyzer/scripts/update_clickhouse_disk_usage.sh` - Disk usage monitoring

### **Code Changes**
- `/home/net/analyzer/dashboard/views.py` - Backend logic for storage management
- `/home/net/analyzer/dashboard/templates/dashboard/log_management.html` - UI updates
- `/home/net/analyzer/dashboard/urls.py` - New API endpoints

### **API Endpoints**
- `GET /log-management/storage/` - Storage information with filesystem data
- `GET /log-management/storage/allocation/` - Current allocation settings
- `POST /log-management/storage/allocation/` - Update allocation settings

## 🔍 **Monitoring Commands**

### **Check Current Status**
```bash
curl -s http://10.12.50.61:8001/log-management/storage/ | jq '.summary'
```

### **View Filesystem Info**
```bash
curl -s http://10.12.50.61:8001/log-management/storage/ | jq '.filesystem'
```

### **Check Table Sizes**
```bash
curl -s http://10.12.50.61:8001/log-management/storage/ | jq '.tables[] | {name, size, rows}'
```

The storage management system now provides accurate, filesystem-aware allocation with automated data retention - solving the original 200GB vs 27GB available space issue.