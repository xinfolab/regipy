import datetime
import os
import json
import struct

#[TODO] 테스트 필요
def _get_shell_bag_zip_content(raw_byte: bytes) -> dict:
    '''
    zip 형식의 raw byte를 파싱하여 파일명과 폴더명을 반환함
    :param raw_byte: 분석할 레지스트리 값
    :return: 파일명과 폴더명, 마지막 접근 시간을 dict 형식으로 반환
    '''
    global name_size1
    global name_size2
    global folder_name1
    global folder_name2

    print('_get_shell_bag_zip_content')

    # 마지막 접근 시간
    raw_data = raw_byte[36:76]
    raw_date_str = raw_data.hex().split('00')[0]
    # [TODO] DateTimeOffset 에 대한 변화은 알 수 없음
    last_access_time = datetime.datetime.fromtimestamp(raw_date_str).strftime('%Y-%m-%d %H:%M:%S')


    try:
        # 폴더 이름 크기
        index = 84
        folder_name_size1 = struct.unpack('<H', raw_byte[index: index + 2])[0]

        index += 4
        folder_name_size2 = struct.unpack('<H', raw_byte[index: index + 2])[0]

        # 폴더 명
        index += 4
        if folder_name_size1 > 0:
            folder_name1 = raw_byte[index: index + folder_name_size1 * 2].decode('utf-8')
            index += folder_name_size1 * 2

            index += 2

        if folder_name_size2 > 0:
            folder_name2 = raw_byte[index: index + folder_name_size2 * 2].decode('utf-8')
            index += folder_name_size2 * 2
            index += 2

    except Exception:
        # 폴더 이름 크기
        index = 60
        folder_name_size1 = struct.unpack('<H', raw_byte[index: index + 2])[0]

        index += 4
        folder_name_size2 = struct.unpack('<H', raw_byte[index: index + 2])[0]

        # 폴더 명
        index += 4
        if folder_name_size1 > 0:
            folder_name1 = raw_byte[index: index + folder_name_size1 * 2].decode('utf-8')
            index += folder_name_size1 * 2

            index += 2

        if folder_name_size2 > 0:
            folder_name2 = raw_byte[index: index + folder_name_size2 * 2].decode('utf-8')
            index += folder_name_size2 * 2

            index += 2

    #[TODO] _get_shell_bag_zip_content 어떤 값이 들어오는지 모름. 확인해야함
    result = {
        'folder_name1': folder_name1,
        'folder_name2': folder_name2,
        'last_access_time': last_access_time
    }

    return result


def _get_folder_name_from_guid(guid: str) -> str:
    '''
    guid를 알고 있는 폴더명으로 변환. 만약 리스트에 없는  '' 반환
    :param guid: guid
    :return: 폴더명
    '''
    json_full_path = os.path.join(
        os.getcwd(),
        'plugins',
        'ntuser',
        'external',
        'guid_to_name.json'
    )
    if not os.path.exists(json_full_path):
        return ''

    with open(json_full_path, 'r', encoding='utf-8') as f:
        json_data = json.load(f)

    try:
        folder_name = json_data[guid]
    except:
        return ''

    return folder_name


def _get_process_guid(raw_bytes: bytes) -> str:
    '''
    raw byte를 process guid로 변환
    :param raw_bytes: guid로 변환 할 byte 값
    :return: guid
    '''
    part1 = raw_bytes[0:4][::-1].hex()
    part2 = raw_bytes[4:6][::-1].hex()
    part3 = raw_bytes[6:8][::-1].hex()
    part4 = raw_bytes[8:10].hex()
    part5 = raw_bytes[10:16].hex()

    return f'{part1}-{part2}-{part3}-{part4}-{part5}'


# [TODO] OpenSaveFilesView의 Last Moidify Time이 매칭 되지 않음
def _extract_date_time_offset_from_bytes(raw_bytes) -> datetime:
    '''
    raw byte를 datetime으로 변환함
    :param raw_bytes: datetime으로 변환 할 byte 값
    :return: UTC 시간, datetime(%Y-%m-%d %H:%M:%S)
    '''
    some_date = struct.unpack('<H', raw_bytes[:2])[0]

    day = some_date & 0x1f
    month = (some_date & 0x1e0) >> 5
    year = ((some_date & 0xfe00) >> 9) + 1980

    some_time = struct.unpack('<H', raw_bytes[2:4])[0]
    some_time_binary = format(some_time, '016b')

    chunk1 = some_time_binary[:5]
    chunk2 = some_time_binary[5:11]
    chunk3 = some_time_binary[11:]

    hour = int(chunk1, 2)
    minute = int(chunk2, 2)
    seconds = int(chunk3, 2)

    try:
        dt = datetime.datetime(year, month, day, hour, minute, seconds)
    except:
        return None

    return dt.strftime('%Y-%m-%d %H:%M:%S')


# =====================================================
def _get_folder_name(raw_bytes: bytes, start_index=4) -> str:
    '''
    raw byte를 guid로 변환하여 알고 있는 폴더 명으로 반환. 만약 guid가 리스트에 없는 경우 '' 반환
    :param raw_byte: 폴더명으로 변환할 byte
    :param start_index: byte에서 파싱을 시작할 index 위치
    :return: 폴더명. 변환이 실패할 경우 '' 반환
    '''
    # size and type pass
    index = start_index

    raw_guid = _get_process_guid(raw_bytes[index: index + 16])
    folder_name = _get_folder_name_from_guid(raw_guid)

    # guid pass
    index += 16

    if index >= len(raw_bytes):
        return folder_name

    size = struct.unpack('<H', raw_bytes[index: index + 2])
    if size == 0:
        return folder_name

    return folder_name


#[TODO] 테스트 필요
def _process_property_view_default(raw_bytes: bytes) -> dict:
    '''
    레지스트리 값을 파싱해 폴더명 반환
    :param raw_bytes: 레지스트리 값
    :return: 폴더명을 dict 형식으로 반환함
    '''
    print('_process_property_view_default')
    index = 10
    shell_property_sheet_list_size = struct.unpack('<H', raw_bytes[index: index + 2])

    index += 2
    identifier_size = struct.unpack('<H', raw_bytes[index: index + 2])

    index += 2
    index += identifier_size

    if shell_property_sheet_list_size > 0:
        # shell_property_sheet_list 파싱하는 코드는 생략
        pass
    else:
        try:
            if raw_bytes[0x28] == 0x2f or \
                    raw_bytes[0x24] == 0x4e and \
                    raw_bytes[0x26] == 0x2f and \
                    raw_bytes[0x28] == 0x41:
                return _get_shell_bag_zip_content(raw_bytes)
        except Exception:
            pass

    index += shell_property_sheet_list_size
    # move past end of property sheet terminator
    index += 2

    index += 16
    raw_guid = _get_process_guid(raw_bytes[index: index + 16])

    index += 16
    folder_name = _get_folder_name_from_guid(raw_guid)

    # ExtentionBlock 파싱하는 코드는 생략함

    result = {
        'folder_name': folder_name
    }

    return result


# =====================================================
def _get_shell_bag_0x2e(raw_bytes: bytes) -> dict:
    '''
    레지스트리 값을 파싱하여 폴더명을 반환함
    :param raw_bytes: 레지스트리 값
    :return: 폴더 명
    '''
    index = 0
    post_sig = raw_bytes[:len(raw_bytes) - 8]
    if post_sig[::-1].hex() == '0000ee306bfe9555':
        # 유저 프로파일 명 반환
        #[TODO] 아직 이곳에 들어오는 데이터는 확인하지 못함
        print('0000ee306bfe9555!!! 테스트하기 위해선 데이터 필요')

    # 폴더 이름 반환
    if raw_bytes[0] == 20 or \
            raw_bytes[0] == 50 or \
            raw_bytes[0] == 58:
        result = {
            'folder_name': _get_folder_name(raw_bytes)
        }
        return result

    if raw_bytes[2] == 83:
        result = {
            'folder_name': _get_folder_name(raw_bytes, start_index=36)
        }
        return result

    try:
        # zip 파일 확인
        if raw_bytes[0x28] == 0x2f or\
                raw_bytes[0x24] == 0x4e and\
                raw_bytes[0x26] == 0x2f and\
                raw_bytes[0x28] == 0x41:
            return _get_shell_bag_zip_content(raw_bytes)
    except Exception:
        pass

    try:
        return _process_property_view_default(raw_bytes)
    except Exception:
        pass

    # Root 폴더 : MPT 디바이스 명 확인

    index = 30
    storage_string_name_len = struct.unpack('<I', raw_bytes[index: index + 4])[0]

    index += 4
    storage_id_string_len = struct.unpack('<I', raw_bytes[index: index + 4])[0]

    index += 4
    file_system_name_len = struct.unpack('<I', raw_bytes[index: index + 4])[0]

    index = 40
    storage_name = struct.unpack('<I', raw_bytes[index: storage_string_name_len * 2 - 2])[0]

    index += storage_string_name_len * 2
    storage_string_id_name = struct.unpack('<I', raw_bytes[index: storage_id_string_len * 2 - 2])[0]

    result = {
        'storage_name': storage_name,
        'storage_string_id_name': storage_string_id_name
    }

    return result


def _get_shell_bag_0x2f(raw_bytes: bytes) -> dict:
    '''
    드라이브 명을 반환함
    :param raw_bytes: 레지스트리 값
    :return: 드라이브 명
    '''
    drive_letter = raw_bytes[3:5].decode()

    result = {
        'drive_letter': drive_letter
    }

    return result


def _get_shell_bag_0x31(raw_bytes: bytes) -> dict:
    '''
    레지스트리 값을 파싱하여 폴더명을 반환함
    :param raw_bytes: 레지스트리 값
    :return: 마지막 수정 시간과 파일명을 dict 형식으로 반환
    '''
    index = 2
    try:
        # zip 파일 확인
        if raw_bytes[0x27] == 0x00 and \
                raw_bytes[0x28] == 0x2f and \
                raw_bytes[0x29] == 0x00 or \
                raw_bytes[0x24] == 0x4e and \
                raw_bytes[0x26] == 0x2f and \
                raw_bytes[0x28] == 0x41:
            return _get_shell_bag_zip_content(raw_bytes)
    except Exception:
        pass

    # 알수 없는 타입은 넘어감
    index += 6
    # 마지막 수정 시간
    last_modification_time = _extract_date_time_offset_from_bytes(raw_bytes[index: index + 4])

    index += 6
    beef_pos = int(raw_bytes.hex().find('0400efbe') / 2)
    #beef0004 시작 위치
    beef_pos -= 4

    if raw_bytes[2] == 0x35:
        len = beef_pos - index
    else:
        len = raw_bytes[index:].find(0x00)
        # [TODO] 영어, 특수문자, 숫자 + 한글 일 때 정상적으로 가져오지 못하기에 임시적으로 해놓음
        if len <= 1:
            len = int(raw_bytes[index:].hex().find('0400efbe')/2)

    temp_byte = raw_bytes[index: index + len]
    index += len

    if raw_bytes[2] == 0x35:
        try:
            folder_name = temp_byte.decode('utf-8')
        except UnicodeDecodeError:
            folder_name = temp_byte[:-2].decode('utf-16', 'replace')
    else:
        try:
            folder_name = temp_byte.decode('utf-8')
        except UnicodeDecodeError:
            index -= len
            len = int(raw_bytes[index:].hex().find('0400efbe')/2)
            temp_byte = raw_bytes[index: index + len - 6]
            folder_name = temp_byte.decode('utf-16', 'replace')

    # shell item data 크기 파싱하는 코드 생략
    # ExtentionBlock 파싱하는 코드 생략

    result = {
        'last_modification_time': last_modification_time,
        'folder_name' : folder_name
    }

    return result


def _get_shell_bag_0x32(raw_bytes: bytes) -> dict:
    '''
    레지스트리 값을 파싱해 파일 사이즈, 파일명, 마지막 수정 시간을 반환함
    :param raw_bytes: 파싱할 레지스트리 값
    :return: 파일 사이즈, 파일명, 마지막 수정 시간을 dict 형식으로 반환
    '''
    index = 2
    try:
        if raw_bytes[0x28] == 0x2f or\
                raw_bytes[0x24] == 0x4e and\
                raw_bytes[0x26] == 0x2f and\
                raw_bytes[0x28] == 0x41:
            return _get_shell_bag_zip_content(raw_bytes)
    except Exception:
        pass

    index += 2
    file_size = struct.unpack('<I', raw_bytes[index: index + 4])[0]

    index += 4
    last_modification_time_raw = raw_bytes[index: index + 4]
    last_modification_time = _extract_date_time_offset_from_bytes(last_modification_time_raw)

    index += 6
    len = raw_bytes[index:].find(0x00)
    temp_byte = raw_bytes[index: index + len]
    try:
        file_name = temp_byte.decode('utf-8')
    except UnicodeDecodeError:
        file_name = temp_byte[:-1].decode('utf-16', 'replace')

    shell_bag_result = {
        'file_size': file_size,
        'file_name': file_name,
        'last_modification_time': last_modification_time
    }

    return shell_bag_result


# [TODO] 테스트 필요
def _get_shell_bag_0x3a(raw_bytes: bytes) -> dict:
    '''
    레지스트리 값을 파싱해 폴더명을 반환함
    :param raw_bytes: 레지스트리 값
    :return: 폴더명을 dict 형식으로 반환
    '''
    print('_get_shell_bag_0x3a')
    index = 10
    size = struct.unpack('<B', raw_bytes[index])[0]

    index += 1
    if raw_bytes[11] == 1:
        index = 12

    raw_val = raw_bytes[index: index + size].decode()
    folder_name = raw_val.split('|')

    result = {
        'folder_name': folder_name[-1:]
    }

    return result


# [TODO] 테스트 필요
def _get_shell_bag_0x61(raw_bytes: bytes) -> dict:
    '''
    레지스트리 값을 파싱해 URI를 반환함
    :param raw_bytes: 레지스트리 값
    :return:
    '''
    print('_get_shell_bag_0x61')
    # 알 수 없는 타입은 넘어감
    index = 3
    flag = raw_bytes[index]

    index += 1
    data_size = struct.unpack('<H', raw_bytes[index: index + 2])[0]

    user_name = ''

    if data_size > 0:
        # 알 수 없는 타입은 넘어감
        index += 10
        print('_get_shell_bag_0x61 반드시 확인하자')
        # [TODO] DateTimeOffset을 이용한 부분은 반드시 확인해야함
        file_time = struct.unpack('<D', raw_bytes[index: index + 2])[0]
        us = (file_time - 116444736000000000) / 10
        file_time = datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds = us)
        last_access_time = file_time.strftime('%Y-%m-%d %H:%M:%S')

        # 알 수 없는 타입은 넘어감
        index += 28
        str_size = struct.unpack('<I', raw_bytes[index: index + 4])

        #[TODO] 사이즈 변환 확인해봐야함
        index += 4
        try:
            temp_size = raw_bytes[index: index + str_size].decode('utf-8')
        except UnicodeDecodeError:
            temp_size = raw_bytes[index: index + str_size].decode('utf-16')

        index += int(temp_size)

        str_size = struct.unpack('<I', raw_bytes[index: index + 4])
        index += 4

        if str_size > 0:
            try:
                user_name = raw_bytes[index: index + str_size].decode('utf-8')
            except UnicodeDecodeError:
                user_name = raw_bytes[index: index + str_size].decode('utf-16')

            index += str_size

        str_size = struct.unpack('<I', raw_bytes[index: index + 4])

        index += 4
        if str_size > 0:
            try:
                user_name = raw_bytes[index: index + str_size].decode('utf-8')
            except UnicodeDecodeError:
                user_name = raw_bytes[index: index + str_size].decode('utf-16')

            index += str_size

        len = raw_bytes[index:].find(0x00)
        try:
            uri = raw_bytes[index: index + len].decode('utf-8')
        except UnicodeDecodeError:
            uri = raw_bytes[index: index + len].decode('utf-16')

        # data size 파싱하는 코드 생략략

    result = {
        'user_name': user_name,
        'last_access_time': last_access_time,
        'uri': uri
    }

    return result


# [TODO] 테스트 필요
def _get_shell_bag_0x71(raw_bytes: bytes) -> dict:
    '''
    레지스트리 값을 파싱해 폴더명을 반환
    :param raw_bytes: 레지스트리 값
    :return: 폴더명을 dict 형식으로 반환
    '''
    print('_get_shell_bag_0x71')
    # 알수 없는 타입은 넘어감
    index = 14
    data_sig = struct.unpack('<I', raw_bytes[:6])[0]
    if str(data_sig) == 'beebee00':
        return _process_property_view_default(raw_bytes)

    if raw_bytes[2] == 0x4d:
        index -= 10

    if len(raw_bytes) == 0x16:
        index = 4

    raw_guid = _get_process_guid(raw_bytes[index: index + 16])
    folder_name = _get_folder_name_from_guid(raw_guid)

    # ExtentionBlock 얻어오는 코드 제거

    result = {
        'folder_name': folder_name
    }
    return result


def _get_shell_bag_0x74(raw_bytes: bytes) -> dict:
    '''
    레지스트리 값을 파싱해 파일 사이즈, 마지막 수정 시간, 폴더명을 반환
    :param raw_bytes: 레지스트리 값
    :return: 파일 사이즈, 마지막 수정 시간, 폴더명을 dict 형식으로 반환
    '''
    index = 4
    size = struct.unpack('<H', raw_bytes[index: index + 2])

    index += 2
    sig74 = raw_bytes[index: index + 4].decode('utf-8')
    if sig74.lower() =='cf\0\0':
        try:
            if raw_bytes[0x28] == 0x2f or \
                    raw_bytes[0x24] == 0x4e and \
                    raw_bytes[0x26] == 0x2f and \
                    raw_bytes[0x28] == 0x41:
                return _get_shell_bag_zip_content(raw_bytes)
        except Exception:
            pass

    if sig74.lower() != 'cfsf':
        raise Exception(f'Invalid signature! Should be CFSF but was {sig74}')

    index += 4
    sub_shell_size = struct.unpack('<H', raw_bytes[index: index + 2])[0]

    index += 2
    sub_class_type = raw_bytes[index]

    # 알 수 없는 타입은 넘어감
    index += 2
    folder_size = struct.unpack('<I', raw_bytes[index: index + 4])[0]

    index += 4
    last_modification_time = _extract_date_time_offset_from_bytes(raw_bytes[index: index + 4])

    index += 6
    len = raw_bytes[index:].find(0x00)

    try:
        folder_name = raw_bytes[index: index+len].decode('utf-8')
    except UnicodeDecodeError:
        folder_name = raw_bytes[index: index+len][:-1].decode('utf-16', 'replace')

    # delegate guid 파싱하는 코드 생략
    # item 파싱하는 코드 생략
    # shell item data size 파싱하는 코드 생략
    # ExtentionBlock 파싱하는 코드 생략

    result = {
        'folder_size': folder_size,
        'last_modification_time': last_modification_time,
        'folder_name': folder_name
    }

    return result


# =====================================================
def _gather_result(output_dict, data: dict) -> dict:
    drive_letter = data.get('drive_letter', None)
    if drive_letter is not None:
        path = os.path.join(output_dict['file_path'], drive_letter)
        output_dict.update(
            {
                'file_path': f'{path}\\'
            }
        )
    folder_name = data.get('folder_name', None)
    if folder_name is not None:
        path = os.path.join(output_dict['file_path'], folder_name)
        output_dict.update(
            {
                'file_path': path
            }
        )
    file_name = data.get('file_name', None)
    if file_name is not None:
        path = os.path.join(output_dict['file_path'], file_name)
        output_dict.update(
            {
                'file_path': path
            }
        )
    last_modification_time = data.get('last_modification_time', None)
    if last_modification_time is not None:
        output_dict.update(
            {
                'last_modification_time': last_modification_time
            }
        )

    file_size = data.get('file_size', None)
    if file_size is not None:
        output_dict.update(
            {
                'file_size': file_size
            }
        )

    return output_dict


def _get_shell_raw(value_data_raw: bytes) -> list:
    '''
    레지스트리 값을 shell raw으로 파싱하여 리스트로 반환
    :param value_data_raw: 레지스트리 값
    :return: shell raw 리스트
    '''
    index = 0
    shell_raw = list()

    while index < len(value_data_raw):
        size = struct.unpack('<H', value_data_raw[index: index + 2])[0]
        if size == 0:
            break
        shell_raw.append(value_data_raw[index: index + size])
        index += size

    return shell_raw


def get_mrulistex_order(read_data: bytes):
    index = 0
    count = 0
    order_dict = dict()

    while True:
        if read_data[index] == 0xff:
            break
        order = str(struct.unpack('<I', read_data[index: index + 4])[0])
        index += 4
        count += 1
        order_dict[order] = count

    return order_dict


def get_opensavepidlmru_entries(read_data: bytes):
    shell_raw = _get_shell_raw(read_data)

    output_dict = {
        'file_path': '',
        'last_modification_time': '',
        'file_size': ''
    }
    try:
        for raw in shell_raw:
            if raw[2] == 0x00:
                print(hex(raw[2]))
            elif raw[2] == 0x1f:
                # 아직 필요한 정보 없음
                pass
            elif raw[2] == 0x2f:
                shell_bag_result = _get_shell_bag_0x2f(raw)
                output_dict = _gather_result(output_dict, shell_bag_result)
            elif raw[2] == 0x2e:
                shell_bag_result = _get_shell_bag_0x2e(raw)
                output_dict = _gather_result(output_dict, shell_bag_result)
            elif raw[2] == 0xb1 or \
                    raw[2] == 0x31 or \
                    raw[2] == 0x35 or \
                    raw[2] == 0x36:
                shell_bag_result = _get_shell_bag_0x31(raw)
                output_dict = _gather_result(output_dict, shell_bag_result)
            elif raw[2] == 0x32:
                shell_bag_result = _get_shell_bag_0x32(raw)
                output_dict = _gather_result(output_dict, shell_bag_result)
            elif raw[2] == 0x3a:
                shell_bag_result = _get_shell_bag_0x3a(raw)
                output_dict = _gather_result(output_dict, shell_bag_result)
            elif raw[2] == 0x71:
                shell_bag_result = _get_shell_bag_0x71(raw)
                output_dict = _gather_result(output_dict, shell_bag_result)
            elif raw[2] == 0x74:
                shell_bag_result = _get_shell_bag_0x74(raw)
                output_dict = _gather_result(output_dict, shell_bag_result)
            elif raw[2] == 0x40:
                print(hex(raw[2]))
            elif raw[2] == 0x61:
                shell_bag_result = _get_shell_bag_0x61(raw)
                output_dict = _gather_result(output_dict, shell_bag_result)
            elif raw[2] == 0xc3:
                # 네트워크 영역
                print(hex(raw[2]))
            else:
                print('not found type')
    except:
        print('except')

    print(output_dict)

    return output_dict