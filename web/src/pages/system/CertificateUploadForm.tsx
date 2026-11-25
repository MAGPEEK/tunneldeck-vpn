import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { isApiError } from '../../api/client';
import { queryKeys } from '../../api/queryKeys';
import { uploadCertificate } from '../../api/remoteAccess';
import { Button } from '../../components/Button';
import { Field, type FieldControlProps } from '../../components/Field';
import { Notice } from '../../components/Notice';
import { genericErrorMessage } from '../auth/formError';
import styles from './SystemPage.module.css';

export function CertificateUploadForm() {
  const { t } = useTranslation();
  const client = useQueryClient();
  const [certificatePem, setCertificatePem] = useState('');
  const [keyPem, setKeyPem] = useState('');
  const upload = useMutation({
    mutationFn: uploadCertificate,
    onSuccess: (result) => {
      client.setQueryData(queryKeys.remoteAccess, result);
      setCertificatePem('');
      setKeyPem('');
    },
  });
  const fields = isApiError(upload.error) ? upload.error.fields : {};

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    upload.mutate({ certificatePem, keyPem });
  };

  const textarea = (value: string, onChange: (value: string) => void) =>
    function PemTextarea(control: FieldControlProps) {
      return (
        <textarea
          {...control}
          className={`${control.className ?? ''} ${styles.mono}`}
          rows={6}
          spellCheck={false}
          autoComplete="off"
          value={value}
          onChange={(event) => onChange(event.currentTarget.value)}
        />
      );
    };

  return (
    <form className={styles.upload} onSubmit={submit}>
      <h3 className={styles.subTitle}>{t('remoteAccess.uploadTitle')}</h3>
      <Field label={t('remoteAccess.certificatePem')} error={fields.certificatePem}>
        {textarea(certificatePem, setCertificatePem)}
      </Field>
      <Field label={t('remoteAccess.keyPem')} error={fields.keyPem}>
        {textarea(keyPem, setKeyPem)}
      </Field>
      {upload.isError && Object.keys(fields).length === 0 && (
        <Notice tone="danger" role="alert">
          {genericErrorMessage(t, upload.error)}
        </Notice>
      )}
      {upload.isSuccess && (
        <Notice tone="info" role="status">
          {t('remoteAccess.uploaded')}
        </Notice>
      )}
      <div className={styles.buttons}>
        <Button
          type="submit"
          loading={upload.isPending}
          disabled={certificatePem.trim() === '' || keyPem.trim() === ''}
        >
          {t('remoteAccess.upload')}
        </Button>
      </div>
    </form>
  );
}
