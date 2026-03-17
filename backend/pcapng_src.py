class Reader(object):

    def __init__(self, fileobj):
        self.name = getattr(fileobj, 'name', '<{0}>'.format(fileobj.__class__.__name__))
        self.__f = fileobj

        shb = SectionHeaderBlock()
        buf = self.__f.read(shb.__hdr_len__)
        if len(buf) < shb.__hdr_len__:
            raise ValueError('invalid pcapng header')

        shb.unpack_hdr(buf)
        if shb.type != PCAPNG_BT_SHB:
            raise ValueError('invalid pcapng header: not a SHB')

        if shb.bom == BYTE_ORDER_MAGIC_LE:
            self.__le = True
            buf += self.__f.read(_swap32b(shb.len) - shb.__hdr_len__)
            shb = SectionHeaderBlockLE(buf)
        elif shb.bom == BYTE_ORDER_MAGIC:
            self.__le = False
            buf += self.__f.read(shb.len - shb.__hdr_len__)
            shb = SectionHeaderBlock(buf)
        else:
            raise ValueError('unknown endianness')

        if shb.v_major != PCAPNG_VERSION_MAJOR:
            raise ValueError('unknown pcapng version {0}.{1}'.format(shb.v_major, shb.v_minor,))

        idb = None
        while 1:
            buf = self.__f.read(8)
            if len(buf) < 8:
                break

            blk_type, blk_len = struct_unpack('<II' if self.__le else '>II', buf)
            buf += self.__f.read(blk_len - 8)

            if blk_type == PCAPNG_BT_IDB:
                idb = (InterfaceDescriptionBlockLE(buf) if self.__le
                       else InterfaceDescriptionBlock(buf))
                break

        if idb is None:
            raise ValueError('IDB not found')

        self._divisor = float(1e6)  
        self._tsoffset = 0
        for opt in idb.opts:
            if opt.code == PCAPNG_OPT_IF_TSRESOL:
                opt_val = struct_unpack('b', opt.data)[0]
                pow_num = 2 if opt_val & 0b10000000 else 10
                self._divisor = float(pow_num ** (opt_val & 0b01111111))

            elif opt.code == PCAPNG_OPT_IF_TSOFFSET:
                self._tsoffset = struct_unpack('<q' if self.__le else '>q', opt.data)[0]

        if idb.linktype in dltoff:
            self.dloff = dltoff[idb.linktype]
        else:
            self.dloff = 0

        self.idb = idb
        self.snaplen = idb.snaplen
        self.filter = ''
        self.__iter = iter(self)

    @property
    def fd(self):
        return self.__f.fileno()

    def fileno(self):
        return self.fd

    def datalink(self):
        return self.idb.linktype

    def setfilter(self, value, optimize=1):
        raise NotImplementedError

    def readpkts(self):
        return list(self)

    def __next__(self):
        return next(self.__iter)
    next = __next__  

    def dispatch(self, cnt, callback, *args):
        processed = 0
        if cnt > 0:
            for _ in range(cnt):
                try:
                    ts, pkt = next(iter(self))
                except StopIteration:
                    break
                callback(ts, pkt, *args)
                processed += 1
        else:
            for ts, pkt in self:
                callback(ts, pkt, *args)
                processed += 1
        return processed

    def loop(self, callback, *args):
        self.dispatch(0, callback, *args)

    def __iter__(self):
        while 1:
            buf = self.__f.read(8)
            if len(buf) < 8:
                break

            blk_type, blk_len = struct_unpack('<II' if self.__le else '>II', buf)
            buf += self.__f.read(blk_len - 8)

            if blk_type == PCAPNG_BT_EPB:
                epb = EnhancedPacketBlockLE(buf) if self.__le else EnhancedPacketBlock(buf)
                ts = self._tsoffset + (((epb.ts_high << 32) | epb.ts_low) / self._divisor)
                yield (ts, epb.pkt_data)
            elif blk_type == PCAPNG_BT_PB:
                pb = PacketBlockLE(buf) if self.__le else PacketBlock(buf)
                ts = self._tsoffset + (((pb.ts_high << 32) | pb.ts_low) / self._divisor)
                yield (ts, pb.pkt_data)
