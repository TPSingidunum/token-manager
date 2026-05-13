package rs.ac.singidunum.tokenmanager.dtos;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public interface ResponseMapper {
    class JacksonHolder {
        static final ObjectMapper objectMapper = new ObjectMapper();
    }

    default String convertToJson() throws JsonProcessingException {
        return JacksonHolder.objectMapper.writeValueAsString(this);
    }}
